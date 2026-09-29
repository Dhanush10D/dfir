#Requires -Version 5.1
<#
.SYNOPSIS
    Windows memory acquisition wrapper around WinPmem (guide 9.3, docs/collection.md).

.DESCRIPTION
    This script NEVER downloads anything. Obtain WinPmem yourself from its official release page,
    verify the release hash / Authenticode signature, copy it to the collection media, and pass
    its path with -WinPmemPath (or place winpmem*.exe next to this script).

    The wrapper checks the tool, elevation and free space, runs "<winpmem> <image>", then hashes
    the image and writes:
        mem_<HOST>_<UTC>.raw                    the image (written by WinPmem)
        mem_<HOST>_<UTC>.raw.sha256             sha256sum-style line
        mem_<HOST>_<UTC>.raw.acquisition.json   tool path/hash/signature, host, operator, UTC times
    Nothing else on the host is written, changed or deleted.

    Exit codes: 0 ok, 2 tool missing/bad arguments, 3 not elevated, 4 not enough space,
    5 acquisition failed.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File acquire-memory-windows.ps1 -OutputDir E:\mem -WinPmemPath E:\tools\winpmem_mini_x64_rc2.exe -CaseRef IR-2026-001
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OutputDir,
    [string]$WinPmemPath = '',
    [string]$CaseRef = '',
    [string]$Operator = ''
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$WrapperVersion = '1.0.0'
$Invariant = [System.Globalization.CultureInfo]::InvariantCulture

function Get-UtcIso([datetime]$Value) {
    return $Value.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", $Invariant)
}

function Stop-With([int]$Code, [string]$Message) {
    [Console]::Error.WriteLine('error: ' + $Message)
    exit $Code
}

# ---- tool: explicit path, else next to this script, else PATH. Never downloaded.
$tool = $null
if ($WinPmemPath) {
    if (Test-Path -LiteralPath $WinPmemPath -PathType Leaf) { $tool = (Get-Item -LiteralPath $WinPmemPath).FullName }
} else {
    $here = Split-Path -Path $PSCommandPath -Parent
    $local = @(Get-ChildItem -LiteralPath $here -Filter 'winpmem*.exe' -File -ErrorAction SilentlyContinue)
    if ($local.Count -gt 0) { $tool = $local[0].FullName }
    if (-not $tool) {
        $cmd = Get-Command -Name 'winpmem*.exe' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cmd) { $tool = $cmd.Source }
    }
}
if (-not $tool) {
    Stop-With 2 ('WinPmem not found. This wrapper does not download tools: obtain WinPmem from its ' +
        'official release page, verify it, and pass -WinPmemPath <path to winpmem*.exe>.')
}

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$elevated = (New-Object System.Security.Principal.WindowsPrincipal($identity)).IsInRole(
    [System.Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $elevated) { Stop-With 3 'memory acquisition needs an elevated (Administrator) session.' }
if (-not $Operator) { $Operator = $identity.Name }

$outFull = [System.IO.Path]::GetFullPath($OutputDir).TrimEnd('\')
[void][System.IO.Directory]::CreateDirectory($outFull)
$started = Get-Date
$stamp = $started.ToUniversalTime().ToString('yyyyMMdd\THHmmss\Z', $Invariant)
$hostName = $env:COMPUTERNAME
$image = Join-Path $outFull ('mem_' + ($hostName -replace '[^A-Za-z0-9._-]', '_') + '_' + $stamp + '.raw')
if (Test-Path -LiteralPath $image) { Stop-With 2 "$image already exists; refusing to overwrite." }

$ram = [int64](Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory
$drive = New-Object System.IO.DriveInfo([System.IO.Path]::GetPathRoot($outFull))
if ($drive.AvailableFreeSpace -lt ($ram + 512MB)) {
    Stop-With 4 ("not enough free space on " + $drive.Name + ": need about " + [math]::Ceiling(($ram + 512MB) / 1GB) + " GB")
}
if ($outFull.StartsWith($env:SystemDrive, [System.StringComparison]::OrdinalIgnoreCase)) {
    Write-Warning 'The image is written to the system drive; prefer external media.'
}

$toolHash = (Get-FileHash -LiteralPath $tool -Algorithm SHA256).Hash.ToLowerInvariant()
$signature = Get-AuthenticodeSignature -LiteralPath $tool
Write-Output ('tool:    ' + $tool)
Write-Output ('sha256:  ' + $toolHash + '  signature: ' + $signature.Status)

$ErrorActionPreference = 'Continue'
$toolOutput = & $tool $image 2>&1 | ForEach-Object {
    if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { [string]$_ }
}
$exitCode = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
$finished = Get-Date
if (-not (Test-Path -LiteralPath $image -PathType Leaf)) {
    Stop-With 5 ("WinPmem did not produce an image (exit code " + $exitCode + ").")
}

$imageItem = Get-Item -LiteralPath $image
$imageHash = (Get-FileHash -LiteralPath $image -Algorithm SHA256).Hash.ToLowerInvariant()
$os = Get-CimInstance -ClassName Win32_OperatingSystem
$record = [ordered]@{
    schema          = 'dfirbench.acquisition/1'
    kind            = 'memory'
    wrapper         = [ordered]@{ name = 'acquire-memory-windows'; version = $WrapperVersion }
    tool            = [ordered]@{ path = $tool; sha256 = $toolHash; signature = [string]$signature.Status; signer = $(if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }); exit_code = $exitCode }
    host            = [ordered]@{ hostname = $hostName; os = ($os.Caption + ' ' + $os.Version); build = $os.BuildNumber; ram_bytes = $ram; timezone = [System.TimeZoneInfo]::Local.Id }
    operator        = $Operator
    case_ref        = $(if ($CaseRef) { $CaseRef } else { $null })
    started_at      = (Get-UtcIso $started)
    finished_at     = (Get-UtcIso $finished)
    image           = [ordered]@{ file = (Split-Path -Path $image -Leaf); size = [int64]$imageItem.Length; sha256 = $imageHash }
    tool_output_tail = @($toolOutput | Select-Object -Last 20)
}
$utf8 = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($image + '.acquisition.json', (ConvertTo-Json -InputObject $record -Depth 5), $utf8)
[System.IO.File]::WriteAllText($image + '.sha256', ($imageHash + '  ' + (Split-Path -Path $image -Leaf) + "`n"), $utf8)
Write-Output ('image:   ' + $image)
Write-Output ('sha256:  ' + $imageHash)
Write-Output 'Upload it as evidence kind "memory" with expected_sha256 set to the hash above.'
exit 0
