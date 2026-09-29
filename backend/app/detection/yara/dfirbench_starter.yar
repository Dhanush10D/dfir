// dfirbench starter rule pack v1 (reviewed). Low-noise, well-known indicators only.
// Trusted configuration: operators add rules via YARA_RULES_DIR (read-only mount), never the API.
// `include` is disabled at compile time; the pack SHA-256 is recorded in every run manifest.

rule EICAR_Test_File : test
{
    meta:
        description = "EICAR anti-malware test string"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
        severity = "info"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Mimikatz_Strings : credential_access
{
    meta:
        description = "Strings of the Mimikatz credential dumping tool"
        attack = "T1003.001"
        severity = "high"
    strings:
        $a = "sekurlsa::logonpasswords" ascii wide nocase
        $b = "gentilkiwi" ascii wide
        $c = "mimikatz" ascii wide nocase
        $d = "lsadump::sam" ascii wide nocase
    condition:
        2 of them
}

rule PowerShell_Encoded_Download : execution
{
    meta:
        description = "PowerShell launched with an encoded command or a download cradle"
        attack = "T1059.001"
        severity = "medium"
    strings:
        $enc = /powershell(\.exe)?["']?\s+[^\r\n]{0,64}-(e|en|enc|enco|encodedcommand)\s+[A-Za-z0-9+\/=]{40,}/ nocase
        $dl1 = "DownloadString(" ascii wide nocase
        $dl2 = "IEX (New-Object Net.WebClient)" ascii wide nocase
    condition:
        any of them
}

rule PHP_Webshell_Generic : webshell
{
    meta:
        description = "PHP code evaluating request parameters"
        attack = "T1505.003"
        severity = "high"
    strings:
        $php = "<?php" nocase
        $e1 = /(eval|assert|system|passthru|shell_exec)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\[/ nocase
        $e2 = /eval\s*\(\s*base64_decode\s*\(/ nocase
    condition:
        $php and any of ($e*)
}

rule UPX_Packed_PE : packer
{
    meta:
        description = "PE packed with UPX"
        severity = "low"
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
    condition:
        uint16(0) == 0x5A4D and $upx0 and $upx1
}
