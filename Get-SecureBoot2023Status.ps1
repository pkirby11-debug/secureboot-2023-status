<#
.SYNOPSIS
    Read-only check: has this PC finished the 2023 Secure Boot certificate update?

.DESCRIPTION
    Uses the signals Microsoft documents for the 2026 Secure Boot certificate rollout:

      Registry  HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing
                  UEFICA2023Status  NotStarted / InProgress / Updated   (Updated = done)
                  UEFICA2023Error   non-zero = the update hit an error
                HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot
                  AvailableUpdates  0x5944 = queued ... 0x4000 = every step finished
      Events    System log, source TPM-WMI
                  1808 fully updated        1801 not applied yet       1800 restart needed
                  1795 firmware error       1796 update error          1802 blocked (known firmware issue)
                  1803 no OEM-signed KEK    1032 blocked by BitLocker configuration
      Firmware  The KEK and DB variables themselves, read with Get-SecureBootUEFI

    Makes no changes. Must run elevated (SYSTEM through Intune or SCCM is fine).

    Default output is ONE line. That suits the Intune Remediations output column
    (2,048-character limit) and SCCM Run Scripts. Use -Detailed for a full object
    you can read at a desk or pipe to Export-Csv.

    Exit codes: 0 = updated, or not applicable (Secure Boot off / legacy BIOS)
                1 = not fully updated (Intune Remediations reports "With issues")

    Intune:  Devices > Scripts and remediations > Create. Upload this as the DETECTION
             script only (no remediation script). Run as SYSTEM (logged-on credentials = No),
             signature check = No, 64-bit PowerShell = Yes, schedule = Daily.
    SCCM:    Software Library > Scripts > Create Script, approve, then right-click a
             collection > Run Script. Results are grouped by exit code and output.

.EXAMPLE
    .\Get-SecureBoot2023Status.ps1

.EXAMPLE
    .\Get-SecureBoot2023Status.ps1 -Detailed

.NOTES
    Sources: Microsoft KB5068202 (registry keys), KB5016061 (event IDs),
             KB5085046 (troubleshooting guide / AvailableUpdates bits).
#>
[CmdletBinding()]
param(
    [switch]$Detailed
)

# ---------- helpers ----------
function Get-RegValue {
    param([string]$Path, [string]$Name)
    try   { return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name }
    catch { return $null }
}

function Get-UefiVarText {
    # Returns a UEFI variable as ASCII text so certificate names can be matched.
    # This is the same check Microsoft documents ("... -match 'Windows UEFI CA 2023'").
    param([string]$Name)
    try {
        $var = Get-SecureBootUEFI -Name $Name -ErrorAction Stop
        if ($null -ne $var -and $null -ne $var.Bytes) {
            return [System.Text.Encoding]::ASCII.GetString($var.Bytes)
        }
    } catch { }
    return $null
}

function Test-HasText {
    # $null = could not read the variable, otherwise $true / $false
    param($Text, [string]$Pattern)
    if ($null -eq $Text) { return $null }
    return ($Text -match [regex]::Escape($Pattern))
}

function ConvertTo-YN {
    param($Value)
    if ($null -eq $Value) { return '?' }
    if ($Value) { return 'Y' }
    return 'N'
}

function ConvertTo-HexText {
    param($Value)
    if ($null -eq $Value) { return '-' }
    return ('0x{0:X}' -f $Value)
}

function ConvertTo-Dash {
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return '-' }
    return "$Value"
}

# ---------- must be elevated ----------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output 'ERROR: run this script elevated (as administrator or SYSTEM).'
    exit 1
}

# ---------- Secure Boot state ----------
$secureBoot = 'Unknown'
try {
    if (Confirm-SecureBootUEFI -ErrorAction Stop) { $secureBoot = 'On' } else { $secureBoot = 'Off' }
} catch {
    if ($_.Exception -is [System.PlatformNotSupportedException] -or
        $_.Exception.Message -match 'not supported on this platform') {
        $secureBoot = 'NotUEFI'
    } else {
        $sbReg = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' 'UEFISecureBootEnabled'
        if ($sbReg -eq 1) { $secureBoot = 'On' } elseif ($sbReg -eq 0) { $secureBoot = 'Off' }
    }
}

# ---------- registry (Windows' own bookkeeping) ----------
$sbKey  = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot'
$svcKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing'

$status      = Get-RegValue $svcKey 'UEFICA2023Status'
$errCode     = Get-RegValue $svcKey 'UEFICA2023Error'
$errEvent    = Get-RegValue $svcKey 'UEFICA2023ErrorEvent'
$confidence  = Get-RegValue $svcKey 'ConfidenceLevel'
$avail       = Get-RegValue $sbKey  'AvailableUpdates'
$availPolicy = Get-RegValue $sbKey  'AvailableUpdatesPolicy'
$hcOptOut    = Get-RegValue $sbKey  'HighConfidenceOptOut'
$muOptIn     = Get-RegValue $sbKey  'MicrosoftUpdateManagedOptIn'

# ---------- firmware (what is actually in UEFI) ----------
$kekText       = Get-UefiVarText 'KEK'
$dbText        = Get-UefiVarText 'db'
$dbDefaultText = Get-UefiVarText 'dbDefault'

$kek2023      = Test-HasText $kekText 'Microsoft Corporation KEK 2K CA 2023'
$dbWin2023    = Test-HasText $dbText  'Windows UEFI CA 2023'
$db3p2011     = Test-HasText $dbText  'Microsoft Corporation UEFI CA 2011'
$db3p2023     = Test-HasText $dbText  'Microsoft UEFI CA 2023'
$dbOrom2023   = Test-HasText $dbText  'Microsoft Option ROM UEFI CA 2023'
$dbDefWin2023 = Test-HasText $dbDefaultText 'Windows UEFI CA 2023'

# The third-party and Option ROM 2023 CAs are only added where the 2011 third-party CA is trusted.
if ($null -eq $kekText -or $null -eq $dbText) {
    $firmwareComplete = $null
} else {
    $thirdPartyOk     = (-not $db3p2011) -or ($db3p2023 -and $dbOrom2023)
    $firmwareComplete = [bool]($kek2023 -and $dbWin2023 -and $thirdPartyOk)
}

# ---------- event log (System, TPM-WMI) ----------
$events = @()
try {
    $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 1032, 1795, 1796, 1799, 1800, 1801, 1802, 1803, 1808 } -MaxEvents 300 -ErrorAction Stop |
                Where-Object { $_.ProviderName -match 'TPM-WMI' })
} catch { }   # "No events were found" also lands here

$latest   = $events | Select-Object -First 1     # Get-WinEvent returns newest first
$last1808 = $events | Where-Object { $_.Id -eq 1808 } | Select-Object -First 1
$last1801 = $events | Where-Object { $_.Id -eq 1801 } | Select-Object -First 1

# 1808 counts only if it is newer than any 1801 ("not applied yet")
$eventSaysDone = ($null -ne $last1808) -and (($null -eq $last1801) -or ($last1808.TimeCreated -ge $last1801.TimeCreated))

# Problems only count if they are recent and newer than the last success event
$since = (Get-Date).AddDays(-30)
if ($last1808 -and $last1808.TimeCreated -gt $since) { $since = $last1808.TimeCreated }
$recentProblem = $events | Where-Object { $_.Id -in 1032, 1795, 1796, 1802, 1803 -and $_.TimeCreated -gt $since } | Select-Object -First 1
$recentReboot  = $events | Where-Object { $_.Id -eq 1800 -and $_.TimeCreated -gt $since } | Select-Object -First 1

# Confidence level: registry first, then the newest device-specific event that carries one
if (-not $confidence) {
    foreach ($e in ($events | Where-Object { $_.Id -in 1795, 1801, 1802, 1803, 1808 })) {
        if ($e.Message -match 'BucketConfidenceLevel:[ \t]*(?<c>[^\r\n]+?)[ \t]*(?:UpdateType:|SkipReason:|For more information|\r|\n|$)') {
            $confidence = $Matches['c'].Trim()
            break
        }
    }
}
$knownIssue = $null
$kiEvt = $events | Where-Object { $_.Id -eq 1802 } | Select-Object -First 1
if ($kiEvt -and $kiEvt.Message -match 'SkipReason:\s*(?<ki>KI_\d+)') { $knownIssue = $Matches['ki'] }

# ---------- Secure-Boot-Update scheduled task ----------
$taskState = 'Unknown'
try {
    $task = Get-ScheduledTask -TaskPath '\Microsoft\Windows\PI\' -TaskName 'Secure-Boot-Update' -ErrorAction Stop
    $taskState = [string]$task.State
} catch [System.Management.Automation.CommandNotFoundException] {
    $taskState = 'Unknown'
} catch {
    $taskState = 'Missing'
}

# ---------- device info (to group results by model / BIOS) ----------
$make = $null; $model = $null; $biosVer = $null; $biosDate = $null; $osBuild = $null
try {
    $cs    = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $make  = $cs.Manufacturer
    $model = $cs.Model
    if ($make -match 'Lenovo') {
        $csp = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Stop
        if ($csp.Version) { $model = $csp.Version }   # friendly name instead of machine type
    }
} catch { }
try {
    $bios    = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
    $biosVer = $bios.SMBIOSBIOSVersion
    if ($bios.ReleaseDate) { $biosDate = ([datetime]$bios.ReleaseDate).ToString('yyyy-MM-dd') }
} catch { }
try {
    $cv      = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    $osBuild = '{0}.{1}' -f $cv.CurrentBuild, $cv.UBR
} catch { }

# ---------- verdict ----------
$isUpdated = ($status -eq 'Updated') -or $eventSaysDone
$hasError  = ($null -ne $errCode) -and ($errCode -ne 0)

if ($secureBoot -eq 'NotUEFI') {
    $result = 'N/A'
    $reason = 'Legacy BIOS (not UEFI) - Secure Boot certificates do not apply'
}
elseif ($secureBoot -eq 'Off') {
    $result = 'N/A'
    $reason = 'Secure Boot is OFF - certificates do not apply until it is turned on'
}
elseif ($isUpdated -and $firmwareComplete -eq $false) {
    $result = 'CHECK'
    $reason = 'Windows says Updated but a 2023 certificate is missing from firmware (BIOS key reset?)'
}
elseif ($isUpdated) {
    $result = 'UPDATED'
    $reason = '2023 certificates and 2023-signed boot manager in place'
}
else {
    $result = 'NOT UPDATED'
    if ($taskState -in 'Disabled', 'Missing') {
        $reason = "Secure-Boot-Update scheduled task is $taskState - the update cannot progress"
    }
    elseif ($avail -eq 0x4100) {
        # Every certificate step is done; only the boot manager step (after a restart) remains
        $reason = 'Restart needed to finish (boot manager step)'
    }
    elseif ($hasError) {
        $reason = 'Update error {0} (event {1}) - see System log, source TPM-WMI' -f (ConvertTo-HexText $errCode), (ConvertTo-Dash $errEvent)
    }
    elseif ($recentProblem) {
        switch ($recentProblem.Id) {
            1802 { $reason = 'Blocked: known firmware issue {0} - check for an OEM BIOS update' -f (ConvertTo-Dash $knownIssue) }
            1803 { $reason = 'Blocked: no OEM-signed KEK for this model (1803) - check with the OEM' }
            1795 { $reason = 'Firmware rejected the update (1795) - update the BIOS' }
            1796 { $reason = 'Update failed (1796) - Windows retries at next restart' }
            1032 { $reason = 'Blocked by BitLocker configuration (1032) - suspend BitLocker for 2 restarts' }
        }
    }
    elseif ($avail -eq 0x4004) {
        $reason = 'Stuck on the KEK step (0x4004) - usually needs an OEM BIOS update or OEM-signed KEK'
    }
    elseif ($recentReboot) {
        $reason = 'Restart needed before the next step can install (1800)'
    }
    elseif ($firmwareComplete -eq $true) {
        $reason = 'Firmware already has the 2023 certificates - Windows still needs to install the 2023-signed boot manager'
    }
    elseif ($status -eq 'InProgress') {
        $reason = 'In progress - the task runs at startup and every 12 hours'
    }
    elseif ($null -eq $status -and $events.Count -eq 0) {
        $reason = 'No Secure Boot servicing data - is a recent cumulative update installed?'
    }
    elseif (-not $avail -and -not $availPolicy) {
        $reason = 'Not started - nothing has triggered the update on this device (AvailableUpdates = 0)'
    }
    else {
        $reason = 'Not started yet'
    }
}

$exitCode = 1
if ($result -in 'UPDATED', 'N/A') { $exitCode = 0 }

# ---------- output ----------
if ($latest) { $lastEvtText = '{0}@{1:yyyy-MM-dd}' -f $latest.Id, $latest.TimeCreated } else { $lastEvtText = 'none' }
if ($db3p2011 -eq $false) { $p3 = 'n/a'; $orom = 'n/a' } else { $p3 = ConvertTo-YN $db3p2023; $orom = ConvertTo-YN $dbOrom2023 }

if ($Detailed) {
    $last1808Time = $null; if ($last1808) { $last1808Time = $last1808.TimeCreated }
    $last1801Time = $null; if ($last1801) { $last1801Time = $last1801.TimeCreated }

    [pscustomobject]@{
        ComputerName                = $env:COMPUTERNAME
        Result                      = $result
        Reason                      = $reason
        SecureBoot                  = $secureBoot
        UEFICA2023Status            = $status
        UEFICA2023Error             = ConvertTo-HexText $errCode
        UEFICA2023ErrorEvent        = $errEvent
        AvailableUpdates            = ConvertTo-HexText $avail
        AvailableUpdatesPolicy      = ConvertTo-HexText $availPolicy
        HighConfidenceOptOut        = $hcOptOut
        MicrosoftUpdateManagedOptIn = $muOptIn
        ConfidenceLevel             = $confidence
        KnownIssue                  = $knownIssue
        KEK_MicrosoftKEK2K2023      = $kek2023
        DB_WindowsUEFICA2023        = $dbWin2023
        DB_Has3rdPartyUEFICA2011    = $db3p2011
        DB_MicrosoftUEFICA2023      = $db3p2023
        DB_OptionROMUEFICA2023      = $dbOrom2023
        DBDefault_WindowsUEFICA2023 = $dbDefWin2023
        LastTpmWmiEvent             = $lastEvtText
        Last1808                    = $last1808Time
        Last1801                    = $last1801Time
        SecureBootUpdateTask        = $taskState
        Manufacturer                = $make
        Model                       = $model
        BIOSVersion                 = $biosVer
        BIOSDate                    = $biosDate
        OSBuild                     = $osBuild
    }
}
else {
    $line = '{0}: {1} | SB={2} | Status={3} | AU={4} | Err={5} | KEK23={6} DB23={7} 3P23={8} OROM23={9} | LastEvt={10} | Conf={11} | Task={12} | OS={13} | {14} {15} | BIOS {16}' -f
        $result, $reason, $secureBoot, (ConvertTo-Dash $status), (ConvertTo-HexText $avail), (ConvertTo-HexText $errCode),
        (ConvertTo-YN $kek2023), (ConvertTo-YN $dbWin2023), $p3, $orom, $lastEvtText, (ConvertTo-Dash $confidence),
        $taskState, (ConvertTo-Dash $osBuild), (ConvertTo-Dash $make), (ConvertTo-Dash $model), (ConvertTo-Dash $biosVer)
    if ($line.Length -gt 2000) { $line = $line.Substring(0, 2000) }
    Write-Output $line
}

exit $exitCode
