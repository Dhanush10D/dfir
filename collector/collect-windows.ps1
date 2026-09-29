#Requires -Version 5.1
<#
.SYNOPSIS
    dfirbench Windows triage collector (guide 9.2, docs/collection.md). Windows PowerShell 5.1.

.DESCRIPTION
    Collects volatile state, event logs, registry hives and selected artifacts into
    <OutputDir>\triage_<HOST>_<YYYYMMDDTHHMMSSZ>.zip with manifest.json (schema dfirbench.triage/1)
    and writes <zip>.sha256 next to it.

    Read-only toward the host:
      * files are read with FileShare ReadWrite|Delete through .NET (never opened for writing),
        paths are always passed with -LiteralPath, reparse points are not followed;
      * wevtutil epl / reg save export into the output directory only;
      * nothing on the host is modified, moved or deleted. The only deletion is the collector's
        own staging folder inside -OutputDir after the zip is written and checked
        (-KeepStaging keeps it);
      * no network traffic unless -NtpServer is given (w32tm /stripchart, one sample);
      * no credential material: SAM/SECURITY hives, browser Login Data/Cookies are not collected.
    Locked or unreadable targets are recorded in the manifest "errors" and collection continues.
    Run elevated for event logs, hives, Prefetch and Tasks; unelevated runs record access errors.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File collect-windows.ps1 -OutputDir E:\triage -CaseRef IR-2026-001

.EXAMPLE
    # With -File, list parameters arrive as one string: separate items with '|'.
    powershell -NoProfile -File collect-windows.ps1 -OutputDir E:\triage -EventLogs 'Security|System' -ExtraPaths 'C:\inetpub\logs|D:\app\app.log'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OutputDir,
    [string]$CaseRef = '',
    [string]$Operator = '',
    [switch]$NoVolatile,
    [switch]$NoEventLogs,
    [switch]$NoFiles,
    [string[]]$EventLogs = @(
        'Security', 'System', 'Application', 'Windows PowerShell',
        'Microsoft-Windows-PowerShell/Operational',
        'Microsoft-Windows-Sysmon/Operational',
        'Microsoft-Windows-TaskScheduler/Operational',
        'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
        'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
        'Microsoft-Windows-Windows Defender/Operational',
        'Microsoft-Windows-WMI-Activity/Operational',
        'Microsoft-Windows-Bits-Client/Operational'
    ),
    [string[]]$ExtraPaths = @(),
    [ValidateRange(1, 65536)][int]$MaxFileMB = 2048,
    [ValidateRange(1, 1048576)][int]$MaxTotalMB = 16384,
    [string]$NtpServer = '',
    [switch]$KeepStaging
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$CollectorName = 'dfirbench-collect-windows'
$CollectorVersion = '1.0.0'
$Schema = 'dfirbench.triage/1'
$Invariant = [System.Globalization.CultureInfo]::InvariantCulture

$script:Files = New-Object System.Collections.ArrayList
$script:Errors = New-Object System.Collections.ArrayList
$script:Skipped = New-Object System.Collections.ArrayList
$script:Names = @{}
$script:TotalBytes = [int64]0
$script:MaxFile = [int64]$MaxFileMB * 1MB
$script:MaxTotal = [int64]$MaxTotalMB * 1MB

function Get-UtcIso {
    param($Value)
    if ($null -eq $Value) { return $null }
    try {
        return ([datetime]$Value).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", $Invariant)
    } catch {
        return $null
    }
}

function Add-CollectionError {
    param([string]$Target, $Problem)
    if ($script:Errors.Count -ge 5000) { return }
    $text = if ($Problem -is [System.Exception]) {
        $Problem.GetType().Name + ': ' + $Problem.Message
    } else {
        [string]$Problem
    }
    if ($text.Length -gt 500) { $text = $text.Substring(0, 500) }
    [void]$script:Errors.Add([ordered]@{ target = $Target; error = $text })
}

function Add-Skipped {
    param([string]$Target, [string]$Reason)
    if ($script:Skipped.Count -ge 5000) { return }
    [void]$script:Skipped.Add([ordered]@{ target = $Target; reason = $Reason })
}

function Invoke-Section {
    param([string]$Name, [scriptblock]$Body)
    try {
        & $Body
    } catch {
        Add-CollectionError -Target $Name -Problem $_.Exception
    }
}

function Get-SafeName {
    param([string]$Name)
    $safe = ($Name -replace '[^A-Za-z0-9._%-]', '_')
    if ($safe.Length -gt 150) { $safe = $safe.Substring(0, 150) }
    if ($safe -eq '' -or $safe -eq '.' -or $safe -eq '..') { $safe = '_' + $safe }
    return $safe
}

function New-RelPath {
    param([string]$Category, [string[]]$Parts)
    $clean = @($Category) + @($Parts | ForEach-Object { Get-SafeName $_ })
    $rel = ($clean -join '/')
    $candidate = $rel
    $n = 1
    while ($script:Names.ContainsKey($candidate.ToLowerInvariant())) {
        $n++
        $candidate = $rel + '~' + $n
    }
    $script:Names[$candidate.ToLowerInvariant()] = $true
    return $candidate
}

function Get-StagePath {
    param([string]$Rel)
    $full = Join-Path $script:Staging ($Rel -replace '/', '\')
    [void][System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($full))
    return $full
}

function Register-File {
    param([string]$Full, [string]$Rel, [string]$Category, [string]$Source, $Extra = $null)
    $item = Get-Item -LiteralPath $Full -Force
    $hash = (Get-FileHash -LiteralPath $Full -Algorithm SHA256).Hash.ToLowerInvariant()
    $script:TotalBytes += $item.Length
    $entry = [ordered]@{
        path         = $Rel
        sha256       = $hash
        size         = [int64]$item.Length
        category     = $Category
        source       = $Source
        collected_at = (Get-UtcIso (Get-Date))
    }
    if ($null -ne $Extra) {
        foreach ($key in $Extra.Keys) { $entry[$key] = $Extra[$key] }
    }
    [void]$script:Files.Add($entry)
}

function Save-Text {
    param([string]$Rel, [string]$Category, [string]$Text, [string]$Source)
    $full = Get-StagePath $Rel
    [System.IO.File]::WriteAllText($full, $Text, (New-Object System.Text.UTF8Encoding($false)))
    Register-File -Full $full -Rel $Rel -Category $Category -Source $Source
}

function Save-Json {
    param([string]$Rel, [string]$Category, $Value, [string]$Source)
    $items = @($Value | Where-Object { $null -ne $_ })
    $json = if ($items.Count -eq 0) { '[]' } else { ConvertTo-Json -InputObject $items -Depth 6 }
    Save-Text -Rel $Rel -Category $Category -Text $json -Source $Source
}

function Invoke-Native {
    # Runs a fixed, read-only system command and returns its combined output as text.
    param([string]$Exe, [string[]]$Arguments)
    $ErrorActionPreference = 'Continue'
    $lines = & $Exe @Arguments 2>&1 | ForEach-Object {
        if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { [string]$_ }
    }
    return (($lines -join "`r`n") + "`r`n")
}

function Save-Command {
    param([string]$Rel, [string]$Category, [string]$Exe, [string[]]$Arguments)
    $label = 'command: ' + $Exe + ' ' + ($Arguments -join ' ')
    try {
        $text = Invoke-Native -Exe $Exe -Arguments $Arguments
        Save-Text -Rel (New-RelPath $Category @($Rel)) -Category $Category -Text $text -Source $label
    } catch {
        Add-CollectionError -Target $label -Problem $_.Exception
    }
}

function Copy-Artifact {
    # Streams one host file into the staging tree without ever opening it for writing.
    param([string]$Source, [string]$Category, [string[]]$Parts, [switch]$QuietMissing)
    try {
        if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
            if (-not $QuietMissing) { Add-Skipped -Target $Source -Reason 'not_found' }
            return
        }
        $item = Get-Item -LiteralPath $Source -Force
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            Add-Skipped -Target $Source -Reason 'reparse_point'
            return
        }
        if ($item.Length -gt $script:MaxFile) {
            Add-Skipped -Target $Source -Reason 'larger_than_max_file_mb'
            return
        }
        if (($script:TotalBytes + $item.Length) -gt $script:MaxTotal) {
            Add-Skipped -Target $Source -Reason 'total_cap_reached'
            return
        }
        $rel = New-RelPath $Category $Parts
        $dest = Get-StagePath $rel
        $share = [System.IO.FileShare]'ReadWrite, Delete'
        $in = [System.IO.File]::Open($Source, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, $share)
        try {
            $out = [System.IO.File]::Open($dest, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            try {
                $in.CopyTo($out, 1048576)
            } finally {
                $out.Dispose()
            }
        } finally {
            $in.Dispose()
        }
        $extra = [ordered]@{
            mtime = (Get-UtcIso $item.LastWriteTimeUtc)
            ctime = (Get-UtcIso $item.CreationTimeUtc)
        }
        Register-File -Full $dest -Rel $rel -Category $Category -Source $Source -Extra $extra
    } catch {
        Add-CollectionError -Target $Source -Problem $_.Exception
    }
}

function Copy-Directory {
    param([string]$Directory, [string]$Filter, [string]$Category, [string[]]$Prefix, [switch]$Recurse)
    try {
        if (-not (Test-Path -LiteralPath $Directory -PathType Container)) { return }
        $items = @(Get-ChildItem -LiteralPath $Directory -Filter $Filter -File -Force -Recurse:$Recurse -ErrorAction SilentlyContinue -ErrorVariable listErrors)
        foreach ($e in @($listErrors)) { Add-CollectionError -Target $Directory -Problem $e.Exception }
        $root = (Get-Item -LiteralPath $Directory -Force).FullName.TrimEnd('\')
    } catch {
        Add-CollectionError -Target $Directory -Problem $_.Exception
        return
    }
    foreach ($f in $items) {
        $relative = $f.FullName.Substring($root.Length).TrimStart('\')
        Copy-Artifact -Source $f.FullName -Category $Category -Parts (@($Prefix) + ($relative -split '\\'))
    }
}

function Save-Hive {
    param([string]$Key, [string]$Category, [string[]]$Parts)
    try {
        $rel = New-RelPath $Category $Parts
        $dest = Get-StagePath $rel
        $text = Invoke-Native -Exe 'reg.exe' -Arguments @('save', $Key, $dest, '/y')
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $dest -PathType Leaf)) {
            Add-CollectionError -Target ('reg save ' + $Key) -Problem ($text.Trim())
            return
        }
        Register-File -Full $dest -Rel $rel -Category $Category -Source ('reg save ' + $Key)
    } catch {
        Add-CollectionError -Target ('reg save ' + $Key) -Problem $_.Exception
    }
}

function Get-CimClassName {
    param($Object)
    if ($null -ne $Object -and $Object.PSObject.Properties['CimClass'] -and $null -ne $Object.CimClass) {
        return [string]$Object.CimClass.CimClassName
    }
    return $null
}

function Split-ListParameter {
    # powershell.exe -File passes an array parameter as one string: accept "a|b" ('|' cannot
    # occur in Windows paths or event log channel names).
    param([string[]]$Values)
    return @($Values | Where-Object { $_ } | ForEach-Object { $_ -split '\|' } | Where-Object { $_ })
}

function Get-RegistryValues {
    param([string]$Path)
    $out = @()
    if (-not (Test-Path -LiteralPath $Path)) { return $out }
    $props = Get-ItemProperty -LiteralPath $Path
    foreach ($p in $props.PSObject.Properties) {
        if ($p.Name -like 'PS*') { continue }
        $out += [ordered]@{ key = $Path; name = $p.Name; value = [string]$p.Value }
    }
    return $out
}

# ----------------------------------------------------------------------------- setup

$started = Get-Date
$EventLogs = Split-ListParameter $EventLogs
$ExtraPaths = Split-ListParameter $ExtraPaths
$stamp = $started.ToUniversalTime().ToString('yyyyMMdd\THHmmss\Z', $Invariant)
$hostName = $env:COMPUTERNAME
if (-not $hostName) { $hostName = 'host' }
$outFull = [System.IO.Path]::GetFullPath($OutputDir).TrimEnd('\')
[void][System.IO.Directory]::CreateDirectory($outFull)
$baseName = 'triage_' + (Get-SafeName $hostName) + '_' + $stamp
$script:Staging = Join-Path $outFull $baseName
$zipPath = $script:Staging + '.zip'
if ((Test-Path -LiteralPath $script:Staging) -or (Test-Path -LiteralPath $zipPath)) {
    Write-Error "output $baseName already exists; refusing to overwrite"
    exit 2
}
[void][System.IO.Directory]::CreateDirectory($script:Staging)

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$elevated = (New-Object System.Security.Principal.WindowsPrincipal($identity)).IsInRole(
    [System.Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $Operator) { $Operator = $identity.Name }
if ($outFull.StartsWith($env:SystemDrive, [System.StringComparison]::OrdinalIgnoreCase)) {
    Write-Warning 'OutputDir is on the system drive; prefer external media or a network share.'
}

# ----------------------------------------------------------------------------- system

$hostInfo = [ordered]@{ hostname = $hostName; fqdn = $null; os = $null; timezone = $null; utc_offset_minutes = $null; boot_time = $null }
Invoke-Section 'system/os_info' {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $tz = [System.TimeZoneInfo]::Local
    $hostInfo.os = ($os.Caption + ' ' + $os.Version).Trim()
    $hostInfo.timezone = $tz.Id
    $hostInfo.utc_offset_minutes = [int]$tz.GetUtcOffset((Get-Date)).TotalMinutes
    $hostInfo.boot_time = Get-UtcIso $os.LastBootUpTime
    if ($cs.PartOfDomain -and $cs.DNSHostName) { $hostInfo.fqdn = ($cs.DNSHostName + '.' + $cs.Domain).ToLowerInvariant() }
    $info = [ordered]@{
        caption = $os.Caption; version = $os.Version; build = $os.BuildNumber
        architecture = $os.OSArchitecture; install_date = (Get-UtcIso $os.InstallDate)
        last_boot = (Get-UtcIso $os.LastBootUpTime); local_time = (Get-UtcIso $os.LocalDateTime)
        timezone_id = $tz.Id; timezone_offset_minutes = $hostInfo.utc_offset_minutes
        domain = $cs.Domain; part_of_domain = $cs.PartOfDomain; manufacturer = $cs.Manufacturer
        model = $cs.Model; logged_on_user = $cs.UserName; memory_bytes = [int64]$cs.TotalPhysicalMemory
        powershell = $PSVersionTable.PSVersion.ToString(); elevated = $elevated
    }
    Save-Json -Rel (New-RelPath 'system' @('os_info.json')) -Category 'system' -Value $info -Source 'Win32_OperatingSystem, Win32_ComputerSystem'
}
Save-Command -Rel 'time_sync.txt' -Category 'system' -Exe 'w32tm.exe' -Arguments @('/query', '/status')

# ----------------------------------------------------------------------------- volatile

if (-not $NoVolatile) {
    Invoke-Section 'volatile/processes' {
        $procs = Get-CimInstance -ClassName Win32_Process | ForEach-Object {
            [ordered]@{
                pid = [int]$_.ProcessId; ppid = [int]$_.ParentProcessId; name = $_.Name
                path = $_.ExecutablePath; cmdline = $_.CommandLine
                created = (Get-UtcIso $_.CreationDate); session = $_.SessionId
            }
        }
        Save-Json -Rel (New-RelPath 'volatile' @('processes.json')) -Category 'volatile' -Value $procs -Source 'Win32_Process'
    }
    Invoke-Section 'volatile/connections' {
        if (Get-Command -Name Get-NetTCPConnection -ErrorAction SilentlyContinue) {
            $tcp = Get-NetTCPConnection -ErrorAction SilentlyContinue | ForEach-Object {
                [ordered]@{
                    proto = 'tcp'; local = ($_.LocalAddress + ':' + $_.LocalPort)
                    remote = ($_.RemoteAddress + ':' + $_.RemotePort); state = [string]$_.State
                    pid = [int]$_.OwningProcess; created = (Get-UtcIso $_.CreationTime)
                }
            }
            $udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object {
                [ordered]@{ proto = 'udp'; local = ($_.LocalAddress + ':' + $_.LocalPort); pid = [int]$_.OwningProcess }
            }
            Save-Json -Rel (New-RelPath 'volatile' @('connections.json')) -Category 'volatile' -Value (@($tcp) + @($udp)) -Source 'Get-NetTCPConnection, Get-NetUDPEndpoint'
        }
    }
    Save-Command -Rel 'netstat.txt' -Category 'volatile' -Exe 'netstat.exe' -Arguments @('-ano')
    Save-Command -Rel 'dns_cache.txt' -Category 'volatile' -Exe 'ipconfig.exe' -Arguments @('/displaydns')
    Save-Command -Rel 'ipconfig.txt' -Category 'volatile' -Exe 'ipconfig.exe' -Arguments @('/all')
    Save-Command -Rel 'arp.txt' -Category 'volatile' -Exe 'arp.exe' -Arguments @('-a')
    Save-Command -Rel 'routes.txt' -Category 'volatile' -Exe 'route.exe' -Arguments @('print')
    Save-Command -Rel 'sessions.txt' -Category 'volatile' -Exe 'query.exe' -Arguments @('user')
    Invoke-Section 'volatile/users' {
        $users = Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=True' | ForEach-Object {
            [ordered]@{ name = $_.Name; sid = $_.SID; disabled = $_.Disabled; description = $_.Description }
        }
        Save-Json -Rel (New-RelPath 'volatile' @('users.json')) -Category 'volatile' -Value $users -Source 'Win32_UserAccount'
    }
    Invoke-Section 'volatile/services' {
        $svc = Get-CimInstance -ClassName Win32_Service | ForEach-Object {
            [ordered]@{
                name = $_.Name; display_name = $_.DisplayName; state = $_.State; start_mode = $_.StartMode
                path = $_.PathName; account = $_.StartName; pid = [int]$_.ProcessId
            }
        }
        Save-Json -Rel (New-RelPath 'volatile' @('services.json')) -Category 'volatile' -Value $svc -Source 'Win32_Service'
    }
    Invoke-Section 'volatile/drivers' {
        $drv = Get-CimInstance -ClassName Win32_SystemDriver | ForEach-Object {
            [ordered]@{ name = $_.Name; state = $_.State; start_mode = $_.StartMode; path = $_.PathName }
        }
        Save-Json -Rel (New-RelPath 'volatile' @('drivers.json')) -Category 'volatile' -Value $drv -Source 'Win32_SystemDriver'
    }
    Invoke-Section 'volatile/shares' {
        $shares = Get-CimInstance -ClassName Win32_Share | ForEach-Object {
            [ordered]@{ name = $_.Name; path = $_.Path; description = $_.Description }
        }
        Save-Json -Rel (New-RelPath 'volatile' @('shares.json')) -Category 'volatile' -Value $shares -Source 'Win32_Share'
    }
    Invoke-Section 'persistence/run_keys' {
        $keys = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        )
        $values = foreach ($k in $keys) { Get-RegistryValues -Path $k }
        Save-Json -Rel (New-RelPath 'persistence' @('run_keys.json')) -Category 'persistence' -Value $values -Source 'registry Run/RunOnce/Winlogon'
    }
    Invoke-Section 'persistence/scheduled_tasks' {
        if (Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue) {
            $tasks = Get-ScheduledTask | ForEach-Object {
                [ordered]@{
                    path = $_.TaskPath; name = $_.TaskName; state = [string]$_.State; author = $_.Author
                    actions = @($_.Actions | Where-Object { $null -ne $_ } | ForEach-Object {
                            if ($_.PSObject.Properties['Execute']) { ([string]$_.Execute + ' ' + [string]$_.Arguments).Trim() } else { Get-CimClassName $_ }
                        })
                    triggers = @($_.Triggers | Where-Object { $null -ne $_ } | ForEach-Object { Get-CimClassName $_ })
                }
            }
            Save-Json -Rel (New-RelPath 'persistence' @('scheduled_tasks.json')) -Category 'persistence' -Value $tasks -Source 'Get-ScheduledTask'
        }
    }
    Invoke-Section 'persistence/wmi_subscriptions' {
        $wmi = [ordered]@{
            filters   = @(Get-CimInstance -Namespace 'root\subscription' -ClassName __EventFilter -ErrorAction SilentlyContinue | ForEach-Object { [ordered]@{ name = $_.Name; query = $_.Query } })
            consumers = @(Get-CimInstance -Namespace 'root\subscription' -ClassName __EventConsumer -ErrorAction SilentlyContinue | ForEach-Object {
                    $c = $_
                    $cmd = if ($c.PSObject.Properties['CommandLineTemplate']) { $c.CommandLineTemplate } elseif ($c.PSObject.Properties['ScriptText']) { $c.ScriptText } else { $null }
                    [ordered]@{ name = $c.Name; class = (Get-CimClassName $c); command = $cmd }
                })
            bindings  = @(Get-CimInstance -Namespace 'root\subscription' -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | ForEach-Object { [ordered]@{ filter = [string]$_.Filter; consumer = [string]$_.Consumer } })
        }
        Save-Json -Rel (New-RelPath 'persistence' @('wmi_subscriptions.json')) -Category 'persistence' -Value $wmi -Source 'root\subscription'
    }
    Invoke-Section 'persistence/startup_commands' {
        $items = Get-CimInstance -ClassName Win32_StartupCommand | ForEach-Object {
            [ordered]@{ name = $_.Name; command = $_.Command; location = $_.Location; user = $_.User }
        }
        Save-Json -Rel (New-RelPath 'persistence' @('startup_commands.json')) -Category 'persistence' -Value $items -Source 'Win32_StartupCommand'
    }
    Invoke-Section 'system/installed_software' {
        $roots = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        )
        $software = foreach ($r in $roots) {
            if (Test-Path -LiteralPath $r) {
                Get-ChildItem -LiteralPath $r -ErrorAction SilentlyContinue | ForEach-Object {
                    $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
                    if ($p -and $p.PSObject.Properties['DisplayName']) {
                        [ordered]@{
                            name = [string]$p.DisplayName
                            version = if ($p.PSObject.Properties['DisplayVersion']) { [string]$p.DisplayVersion } else { $null }
                            publisher = if ($p.PSObject.Properties['Publisher']) { [string]$p.Publisher } else { $null }
                            install_date = if ($p.PSObject.Properties['InstallDate']) { [string]$p.InstallDate } else { $null }
                        }
                    }
                }
            }
        }
        Save-Json -Rel (New-RelPath 'system' @('installed_software.json')) -Category 'system' -Value $software -Source 'registry Uninstall keys'
    }
}

# ----------------------------------------------------------------------------- event logs

if (-not $NoEventLogs) {
    foreach ($channel in $EventLogs) {
        try {
            $rel = New-RelPath 'logs' @(($channel -replace '/', '%4') + '.evtx')
            $dest = Get-StagePath $rel
            $text = Invoke-Native -Exe 'wevtutil.exe' -Arguments @('epl', $channel, $dest)
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $dest -PathType Leaf)) {
                Add-CollectionError -Target ('wevtutil epl ' + $channel) -Problem ($text.Trim())
                continue
            }
            Register-File -Full $dest -Rel $rel -Category 'logs' -Source ('wevtutil epl ' + $channel)
        } catch {
            Add-CollectionError -Target ('wevtutil epl ' + $channel) -Problem $_.Exception
        }
    }
}

# ----------------------------------------------------------------------------- files

if (-not $NoFiles) {
    $win = $env:SystemRoot
    Save-Hive -Key 'HKLM\SYSTEM' -Category 'files' -Parts @('registry', 'SYSTEM')
    Save-Hive -Key 'HKLM\SOFTWARE' -Category 'files' -Parts @('registry', 'SOFTWARE')
    Copy-Artifact -Source (Join-Path $win 'AppCompat\Programs\Amcache.hve') -Category 'files' -Parts @('registry', 'Amcache.hve')
    Copy-Artifact -Source (Join-Path $win 'System32\sru\SRUDB.dat') -Category 'files' -Parts @('srum', 'SRUDB.dat')
    Copy-Artifact -Source (Join-Path $win 'System32\drivers\etc\hosts') -Category 'system' -Parts @('hosts')
    Copy-Directory -Directory (Join-Path $win 'Prefetch') -Filter '*.pf' -Category 'files' -Prefix @('prefetch')
    Copy-Directory -Directory (Join-Path $win 'System32\Tasks') -Filter '*' -Category 'persistence' -Prefix @('tasks') -Recurse
    Copy-Directory -Directory (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp') -Filter '*' -Category 'persistence' -Prefix @('startup', 'all_users')

    $profiles = @()
    try {
        $profiles = @(Get-CimInstance -ClassName Win32_UserProfile | Where-Object { -not $_.Special -and $_.LocalPath })
    } catch {
        Add-CollectionError -Target 'Win32_UserProfile' -Problem $_.Exception
    }
    foreach ($prof in $profiles) {
      try {
        $profileDir = $prof.LocalPath
        $user = Split-Path -Path $profileDir -Leaf
        if ($prof.Loaded) {
            Save-Hive -Key ('HKU\' + $prof.SID) -Category 'files' -Parts @('users', $user, 'NTUSER.DAT')
            Save-Hive -Key ('HKU\' + $prof.SID + '_Classes') -Category 'files' -Parts @('users', $user, 'UsrClass.dat')
        } else {
            Copy-Artifact -Source (Join-Path $profileDir 'NTUSER.DAT') -Category 'files' -Parts @('users', $user, 'NTUSER.DAT') -QuietMissing
            Copy-Artifact -Source (Join-Path $profileDir 'AppData\Local\Microsoft\Windows\UsrClass.dat') -Category 'files' -Parts @('users', $user, 'UsrClass.dat') -QuietMissing
        }
        Copy-Artifact -Source (Join-Path $profileDir 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt') -Category 'files' -Parts @('users', $user, 'ConsoleHost_history.txt') -QuietMissing
        Copy-Directory -Directory (Join-Path $profileDir 'AppData\Roaming\Microsoft\Windows\Recent') -Filter '*.lnk' -Category 'files' -Prefix @('users', $user, 'recent')
        Copy-Directory -Directory (Join-Path $profileDir 'AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations') -Filter '*' -Category 'files' -Prefix @('users', $user, 'jumplists')
        Copy-Directory -Directory (Join-Path $profileDir 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup') -Filter '*' -Category 'persistence' -Prefix @('startup', $user)
        foreach ($browser in @(
                @{ name = 'chrome'; dir = 'AppData\Local\Google\Chrome\User Data' },
                @{ name = 'edge'; dir = 'AppData\Local\Microsoft\Edge\User Data' })) {
            $base = Join-Path $profileDir $browser.dir
            if (Test-Path -LiteralPath $base -PathType Container) {
                Get-ChildItem -LiteralPath $base -Directory -Force -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' } |
                    ForEach-Object {
                        Copy-Artifact -Source (Join-Path $_.FullName 'History') -Category 'browser' -Parts @($user, $browser.name, $_.Name, 'History') -QuietMissing
                    }
            }
        }
        $ff = Join-Path $profileDir 'AppData\Roaming\Mozilla\Firefox\Profiles'
        if (Test-Path -LiteralPath $ff -PathType Container) {
            Get-ChildItem -LiteralPath $ff -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
                foreach ($name in @('places.sqlite', 'places.sqlite-wal')) {
                    Copy-Artifact -Source (Join-Path $_.FullName $name) -Category 'browser' -Parts @($user, 'firefox', $_.Name, $name) -QuietMissing
                }
            }
        }
      } catch {
        Add-CollectionError -Target ('profile ' + $prof.LocalPath) -Problem $_.Exception
      }
    }
}

foreach ($extra in $ExtraPaths) {
    try {
        if (Test-Path -LiteralPath $extra -PathType Leaf) {
            Copy-Artifact -Source $extra -Category 'files' -Parts @('extra', (Split-Path -Path $extra -Leaf))
        } elseif (Test-Path -LiteralPath $extra -PathType Container) {
            Copy-Directory -Directory $extra -Filter '*' -Category 'files' -Prefix @('extra', (Split-Path -Path $extra -Leaf))
        } else {
            Add-CollectionError -Target $extra -Problem 'not found'
        }
    } catch {
        Add-CollectionError -Target $extra -Problem $_.Exception
    }
}

# ----------------------------------------------------------------------------- manifest + zip

$clock = [ordered]@{ source = 'w32tm'; synchronized = $null; ntp_offset_s = $null }
if ($NtpServer) {
    try {
        $sample = Invoke-Native -Exe 'w32tm.exe' -Arguments @('/stripchart', ('/computer:' + $NtpServer), '/samples:1', '/dataonly')
        $m = [regex]::Match($sample, '([+-]\d+\.\d+)s')
        if ($m.Success) { $clock.ntp_offset_s = [double]::Parse($m.Groups[1].Value, $Invariant) }
        $clock['ntp_server'] = $NtpServer
    } catch {
        Add-CollectionError -Target 'w32tm /stripchart' -Problem $_.Exception
    }
}
$selfHash = $null
if ($PSCommandPath) { $selfHash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant() }
$manifest = [ordered]@{
    schema      = $Schema
    collector   = [ordered]@{ name = $CollectorName; version = $CollectorVersion; sha256 = $selfHash; runtime = ('powershell ' + $PSVersionTable.PSVersion.ToString()) }
    host        = $hostInfo
    operator    = $Operator
    case_ref    = $(if ($CaseRef) { $CaseRef } else { $null })
    mode        = 'live'
    elevated    = $elevated
    started_at  = (Get-UtcIso $started)
    finished_at = (Get-UtcIso (Get-Date))
    clock       = $clock
    limits      = [ordered]@{ max_file_mb = $MaxFileMB; max_total_mb = $MaxTotalMB }
    files       = $script:Files
    errors      = $script:Errors
    skipped     = $script:Skipped
}
$manifestPath = Join-Path $script:Staging 'manifest.json'
$manifestJson = ConvertTo-Json -InputObject $manifest -Depth 8
[System.IO.File]::WriteAllText($manifestPath, $manifestJson, (New-Object System.Text.UTF8Encoding($false)))

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::Open($zipPath, [System.IO.Compression.ZipArchiveMode]::Create)
try {
    foreach ($f in $script:Files) {
        $full = Join-Path $script:Staging ($f.path -replace '/', '\')
        [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $full, $f.path, [System.IO.Compression.CompressionLevel]::Optimal)
    }
    [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $manifestPath, 'manifest.json', [System.IO.Compression.CompressionLevel]::Optimal)
} finally {
    $zip.Dispose()
}

$check = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
try {
    $entries = $check.Entries.Count
} finally {
    $check.Dispose()
}
$zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
[System.IO.File]::WriteAllText($zipPath + '.sha256', ($zipHash + '  ' + (Split-Path -Path $zipPath -Leaf) + "`n"), (New-Object System.Text.UTF8Encoding($false)))

if ($entries -eq ($script:Files.Count + 1) -and -not $KeepStaging) {
    # Only the collector's own staging folder, created above inside the output directory.
    $stageFull = [System.IO.Path]::GetFullPath($script:Staging)
    if ($stageFull.StartsWith($outFull + '\', [System.StringComparison]::OrdinalIgnoreCase) -and (Split-Path -Path $stageFull -Leaf) -eq $baseName) {
        Remove-Item -LiteralPath $stageFull -Recurse -Force
    }
} elseif ($entries -ne ($script:Files.Count + 1)) {
    Write-Warning "zip has $entries entries, expected $($script:Files.Count + 1); staging kept at $($script:Staging)"
}

Write-Output ('bundle:  ' + $zipPath)
Write-Output ('sha256:  ' + $zipHash)
Write-Output ('files:   ' + $script:Files.Count + ' collected, ' + $script:Errors.Count + ' errors, ' + $script:Skipped.Count + ' skipped')
exit 0
