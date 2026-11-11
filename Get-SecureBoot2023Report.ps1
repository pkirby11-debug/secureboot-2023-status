<#
.SYNOPSIS
    Builds a Secure Boot 2023 certificate report from the Get-SecureBoot2023Status.ps1
    Intune Remediation results: one row per device, with what to do next.

.DESCRIPTION
    Reads each device's one-line detection output (from Microsoft Graph, or from a CSV
    export of the Remediation's Device status page). A Remediation assigned to users
    records one row per signed-in user, so shared PCs repeat; the report keeps one row per
    device name (the newest result wins) and lists every user on it.

    Each device lands in one category, in this order:

      No fix path              Firmware-blocked AND the PC maker has no BIOS update planned.
                               Replace, or document as an exception.
      Needs BIOS update        Firmware-blocked, and the PC maker has a BIOS that fixes it.
      Blocked - check OEM      Firmware-blocked; the model's PC-maker status isn't recorded yet.
      Restart                  Windows is waiting on a reboot (0x4100, event 1800, 0x8007015E).
      Windows 10 not patching  Windows 10 stopped at the October 2025 update or earlier.
      Behind on updates        Older build than most of the fleet, or no Secure Boot servicing
                               data. Fix patching first.
      Start the update         Patched, but nothing has started the certificate update.
      Virtual machines         VMs that haven't finished; the fix may be the image or the host.
      Secure Boot off
      Legacy BIOS
      Investigate              CHECK or ERROR results, or output that couldn't be read.
      No result yet            The detection script hasn't reported for this device.
      In progress
      Updated

    Firmware-blocked = a signal Microsoft documents as needing the PC maker: event 1803 (no
    OEM-signed KEK), 1795 (firmware rejected the update), 1802 (known firmware issue),
    AvailableUpdates stuck at 0x4004 without a pending reboot, or confidence level
    "Not Supported - Known Limitation" / "Temporarily Paused".

    "Behind" compares each device's build with the two most common builds for its Windows
    version among updated devices in the same data, so it measures against your own fleet.

    A device can't tell you whether its maker plans a BIOS update, so that comes from a
    small CSV you keep (oem-model-status.csv). The first run creates it with every
    firmware-blocked model and a link to that maker's Secure Boot page; later runs add
    newly seen models at the bottom. For each model, set OemStatus to:
        NoBiosPlanned   the maker has no BIOS update with the 2023 certificates
        BiosAvailable   a BIOS with the 2023 certificates exists (put it in FixedInBios)
    and leave it blank until you know. Then run the report again.

    Note: "no BIOS planned" alone does not mean a PC can't get the certificates - Windows
    Update can still install them on many of those models. Only devices that are ALSO
    firmware-blocked land in "No fix path".

.PARAMETER RemediationName
    Display name of the Remediation in Intune (wildcards allowed). Default: *Secure*Boot*

.PARAMETER RemediationId
    The Remediation's ID, if you'd rather not look it up by name.

.PARAMETER InputCsv
    Use an exported CSV instead of Graph: Intune > Scripts and remediations > your package
    > Device status > Export. Needs a device name column and the detection output column.

.PARAMETER OutputFolder
    Where the report files go. Default: .\SecureBoot2023-Report

.PARAMETER OemStatusCsv
    Your PC-maker status table. Default: <OutputFolder>\oem-model-status.csv

.PARAMETER VendorPattern
    Optional regular expression for vendor-managed systems (for example medical imaging
    workstations), matched against device names and users. Matching devices get a note to
    check with the vendor before changing them. Example: -VendorPattern '^MED-|IMAGING'

.PARAMETER PassThru
    Also return the per-device rows to the pipeline.

.EXAMPLE
    .\Get-SecureBoot2023Report.ps1
.EXAMPLE
    .\Get-SecureBoot2023Report.ps1 -RemediationName 'Secure Boot 2023 cert status'
.EXAMPLE
    .\Get-SecureBoot2023Report.ps1 -InputCsv .\DeviceStatus.csv -VendorPattern '^MED-'

.NOTES
    Graph mode needs the Microsoft.Graph.Authentication module and the delegated Graph
    permissions DeviceManagementScripts.Read.All and DeviceManagementManagedDevices.Read.All.
    Read-only: it changes nothing in Intune or on devices.
#>
[CmdletBinding(DefaultParameterSetName = 'GraphByName')]
param(
    [Parameter(ParameterSetName = 'GraphByName')]
    [string]$RemediationName = '*Secure*Boot*',

    [Parameter(ParameterSetName = 'GraphById', Mandatory = $true)]
    [string]$RemediationId,

    [Parameter(ParameterSetName = 'Csv', Mandatory = $true)]
    [string]$InputCsv,

    [string]$OutputFolder = (Join-Path -Path (Get-Location).Path -ChildPath 'SecureBoot2023-Report'),

    [string]$OemStatusCsv,

    [string]$VendorPattern,

    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'
# UTF-8 with BOM so Excel shows accented names correctly (PowerShell 7 needs 'utf8BOM' for that)
$csvEncoding = 'UTF8'
if ($PSVersionTable.PSVersion.Major -ge 6) { $csvEncoding = 'utf8BOM' }
if (-not $OemStatusCsv) { $OemStatusCsv = Join-Path -Path $OutputFolder -ChildPath 'oem-model-status.csv' }

# ---------- where to look up each PC maker (from Microsoft's OEM directory) ----------
$OemDirectory = 'https://support.microsoft.com/en-us/topic/original-equipment-manufacturer-oem-pages-for-secure-boot-9ecc3ba4-fb50-4bd3-9e9b-f16b35b8fb68'
$VmPattern    = 'Virtual Machine|VMware|VirtualBox|KVM|QEMU|Xen|Parallels'

function Get-OemLink {
    param([string]$Model)
    switch -Regex ($Model) {
        $VmPattern                       { return 'Virtual machine: its firmware comes from the hypervisor or cloud platform, not a BIOS' }
        '^Dell'                          { return 'https://www.dell.com/support/kbdoc/000347876/microsoft-2011-secure-boot-certificate-expiration (no-BIOS-planned list: https://www.dell.com/support/kbdoc/000378734)' }
        '^(HP|Hewlett)'                  { return 'https://support.hp.com/document/ish_13070353-13070429-16' }
        '^Lenovo'                        { return 'https://support.lenovo.com/us/en/solutions/HT518129' }
        '^Microsoft Corporation Surface' { return 'https://support.microsoft.com/en-us/surface/surface-secure-boot-certificates-532abf3b-bafe-420f-b615-bf174105549e' }
        '^Panasonic'                     { return 'https://global-pc-support.connect.panasonic.com/info/in260205' }
        '^Acer'                          { return 'https://community.acer.com/kb/articles/18840-update-your-secure-boot-certificates-in-june-2026-to-stay-protected' }
        '^ASUS'                          { return 'https://www.asus.com/us/support/faq/1055903/' }
        default                          { return $OemDirectory }
    }
}

# Windows 11 end of updates for Enterprise/Education editions (Microsoft release health)
$WinInfo = @{
    '17763' = @{ Name = 'Windows 10 1809 / LTSC 2019' }
    '19045' = @{ Name = 'Windows 10 22H2' }
    '22621' = @{ Name = 'Windows 11 22H2'; EndOfUpdates = '2025-10-14' }
    '22631' = @{ Name = 'Windows 11 23H2'; EndOfUpdates = '2026-11-10' }
    '26100' = @{ Name = 'Windows 11 24H2'; EndOfUpdates = '2027-10-12' }
    '26200' = @{ Name = 'Windows 11 25H2'; EndOfUpdates = '2028-10-10' }
    '26300' = @{ Name = 'Windows 11 26H2'; EndOfUpdates = '2029-10-09' }
    '28000' = @{ Name = 'Windows 11 26H1'; EndOfUpdates = '2029-03-13' }
}
$Win10LastNonEsu = 6456   # 19045.6456 = KB5066791, October 14, 2025

# ---------- parse one detection line from Get-SecureBoot2023Status.ps1 ----------
function ConvertFrom-StatusLine {
    param($Text)
    $o = [ordered]@{
        Result = $null; Reason = $null; SB = $null; Status = $null; AU = $null; Err = $null
        KEK23 = $null; DB23 = $null; '3P23' = $null; OROM23 = $null
        LastEvt = $null; Conf = $null; Task = $null; OS = $null; Model = $null; BIOS = $null
    }
    if ($null -eq $Text -or "$Text".Trim() -eq '') { return [pscustomobject]$o }

    # Use the last line that looks like our output (in case anything else was printed)
    $lines = @("$Text" -split "`r?`n" | Where-Object { $_.Trim() -ne '' })
    $line  = $lines | Where-Object { $_ -match '^\s*(UPDATED|NOT UPDATED|CHECK|N/A|ERROR):' } | Select-Object -Last 1
    if (-not $line) { $line = $lines[-1] }
    $line = $line.Trim()

    $parts = $line -split ' \| '
    $head  = $parts[0]
    $i = $head.IndexOf(': ')
    if ($i -gt 0 -and $head.Substring(0, $i) -match '^(UPDATED|NOT UPDATED|CHECK|N/A|ERROR)$') {
        $o.Result = $head.Substring(0, $i)
        $o.Reason = $head.Substring($i + 2)
    } else {
        $o.Result = 'UNREADABLE'
        $o.Reason = $line
    }
    foreach ($p in ($parts | Select-Object -Skip 1)) {
        if ($p -like 'BIOS *') { $o.BIOS = $p.Substring(5); continue }
        if ($p -like 'KEK23=*') {
            foreach ($kv in ($p -split ' ')) {
                $pair = $kv -split '=', 2
                if ($pair.Count -eq 2 -and $o.Contains($pair[0])) { $o[$pair[0]] = $pair[1] }
            }
            continue
        }
        if ($p -match '^(SB|Status|AU|Err|LastEvt|Conf|Task|OS)=(.*)$') { $o[$Matches[1]] = $Matches[2]; continue }
        if (-not $o.Model) { $o.Model = $p }
    }
    return [pscustomobject]$o
}

function Get-OemState {
    param($Row)
    if ($null -eq $Row -or -not $Row.OemStatus) { return 'Unknown' }
    $s = "$($Row.OemStatus)".Trim()
    if ($s -match '^(no ?bios|no ?update|none|eol|end of life|out of scope)') { return 'NoBiosPlanned' }
    if ($s -match '^(bios ?available|available|fixed|yes)') { return 'BiosAvailable' }
    return 'Unknown'
}

function Get-OsMajor {
    param($Os)
    if ($Os -and "$Os" -match '^(\d+)\.\d+$') { return $Matches[1] }
    return ''
}

function Get-OsUbr {
    param($Os)
    if ($Os -and "$Os" -match '^\d+\.(\d+)$') { return [int]$Matches[1] }
    return $null
}

function ConvertTo-DateOrNull {
    param($Value)
    $dt = [datetime]::MinValue
    if ($Value -and [datetime]::TryParse("$Value", [ref]$dt)) { return $dt }
    return $null
}

# ---------- collect device results ----------
$rows = New-Object System.Collections.Generic.List[object]

if ($PSCmdlet.ParameterSetName -eq 'Csv') {
    if (-not (Test-Path -Path $InputCsv)) { throw "Input file not found: $InputCsv" }
    $csv = @(Import-Csv -Path $InputCsv)
    if ($csv.Count -eq 0) { throw "No rows in $InputCsv" }
    $cols = @($csv[0].PSObject.Properties.Name)

    $nameCol = $cols | Where-Object { $_ -match '^\s*device\s*name\s*$' } | Select-Object -First 1
    if (-not $nameCol) { $nameCol = $cols | Where-Object { $_ -match 'device.*name' } | Select-Object -First 1 }
    if (-not $nameCol) { $nameCol = $cols | Where-Object { $_ -match '^\s*(device|computer|computer\s*name|name)\s*$' } | Select-Object -First 1 }
    $outCol = $cols | Where-Object { $_ -match 'pre.*detection.*output' } | Select-Object -First 1
    if (-not $outCol) { $outCol = $cols | Where-Object { $_ -match 'detection.*output' -and $_ -notmatch 'post' } | Select-Object -First 1 }
    if (-not $outCol) { $outCol = $cols | Where-Object { $_ -match 'output' -and $_ -notmatch 'post|error' } | Select-Object -First 1 }
    # Pick columns by preference, so a UserId GUID or the agent's check-in time isn't used by mistake
    $userCol = $null
    foreach ($pattern in '^\s*upn\s*$', 'user\s*principal', 'primary\s*user', '^\s*user\s*name\s*$', 'upn') {
        $userCol = $cols | Where-Object { $_ -match $pattern } | Select-Object -First 1
        if ($userCol) { break }
    }
    $lastCol = $null
    foreach ($pattern in 'last\s*state\s*update', '^\s*modified\s*time\s*$', 'last\s*run', '^\s*last\s*updated\s*$', 'modified') {
        $lastCol = $cols | Where-Object { $_ -match $pattern } | Select-Object -First 1
        if ($lastCol) { break }
    }
    $serialCol = $cols | Where-Object { $_ -match 'serial' } | Select-Object -First 1

    if (-not $nameCol -or -not $outCol) {
        throw ("Couldn't find the device name and detection output columns in {0}. Columns found: {1}" -f $InputCsv, ($cols -join ', '))
    }
    foreach ($c in $csv) {
        $user = $null; $serial = $null; $last = $null
        if ($userCol)   { $user   = $c.$userCol }
        if ($serialCol) { $serial = $c.$serialCol }
        if ($lastCol)   { $last   = $c.$lastCol }
        $rows.Add([pscustomobject]@{ DeviceName = $c.$nameCol; User = $user; Serial = $serial; LastRun = $last; Output = $c.$outCol })
    }
}
else {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw 'Graph mode needs the Microsoft.Graph.Authentication module (Install-Module Microsoft.Graph.Authentication -Scope CurrentUser). Or export the Device status CSV from Intune and use -InputCsv.'
    }
    Import-Module Microsoft.Graph.Authentication
    $scopes = 'DeviceManagementScripts.Read.All', 'DeviceManagementManagedDevices.Read.All'
    $ctx = Get-MgContext
    if (-not $ctx -or @($scopes | Where-Object { $ctx.Scopes -notcontains $_ }).Count -gt 0) {
        $connect = @{ Scopes = $scopes }
        if ((Get-Command Connect-MgGraph).Parameters.ContainsKey('NoWelcome')) { $connect.NoWelcome = $true }
        Connect-MgGraph @connect | Out-Null
    }

    function Get-GraphPaged {
        param([string]$Uri)
        $all = New-Object System.Collections.Generic.List[object]
        while ($Uri) {
            $resp = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject
            foreach ($v in @($resp.value)) { if ($null -ne $v) { $all.Add($v) } }
            $Uri = $resp.'@odata.nextLink'
        }
        return $all.ToArray()
    }

    if (-not $RemediationId) {
        $pkgs = @(Get-GraphPaged -Uri 'https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts' |
                  Where-Object { $_.displayName -like $RemediationName })
        if ($pkgs.Count -eq 0) { throw "No Remediation matches '$RemediationName'. Pass -RemediationName with its exact name, or -RemediationId." }
        if ($pkgs.Count -gt 1) {
            throw ("More than one Remediation matches '{0}': {1}. Pass -RemediationName with the exact name, or -RemediationId." -f $RemediationName, (($pkgs | ForEach-Object { $_.displayName }) -join '; '))
        }
        $RemediationId = $pkgs[0].id
        Write-Host "Remediation: $($pkgs[0].displayName)"
    }

    $states = @(Get-GraphPaged -Uri ('https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/' + $RemediationId + '/deviceRunStates?$expand=managedDevice'))
    foreach ($s in $states) {
        $md = $s.managedDevice
        $name = $null; $user = $null; $serial = $null
        if ($md) { $name = $md.deviceName; $user = $md.userPrincipalName; $serial = $md.serialNumber }
        $rows.Add([pscustomobject]@{ DeviceName = $name; User = $user; Serial = $serial; LastRun = $s.lastStateUpdateDateTime; Output = $s.preRemediationDetectionScriptOutput })
    }
}

if ($rows.Count -eq 0) { throw 'No device results found.' }

# ---------- one row per device (newest result wins; users are combined) ----------
$groups = [ordered]@{}
$n = 0
foreach ($r in $rows) {
    $n++
    $key = "$($r.DeviceName)".Trim().ToUpperInvariant()
    if (-not $key) { $key = "(no name) #$n" }
    if (-not $groups.Contains($key)) { $groups[$key] = New-Object System.Collections.Generic.List[object] }
    $groups[$key].Add($r)
}
$devices = foreach ($key in $groups.Keys) {
    $g = $groups[$key]
    $withResult = @($g | Where-Object { "$($_.Output)".Trim() -ne '' })
    $pick = $g[0]
    if ($withResult.Count -gt 0) {
        $pick = $withResult[0]
        $newest = $null
        foreach ($w in $withResult) {
            $dt = ConvertTo-DateOrNull $w.LastRun
            if ($dt -and (-not $newest -or $dt -gt $newest)) { $newest = $dt; $pick = $w }
        }
    }
    $users = @($g | ForEach-Object { "$($_.User)".Trim() } | Where-Object { $_ } | Sort-Object -Unique)
    $displayName = $pick.DeviceName
    if (-not "$displayName".Trim()) { $displayName = '(no name in export)' }
    [pscustomobject]@{
        DeviceName = $displayName
        Users      = $users -join '; '
        Serial     = $pick.Serial
        LastRun    = $pick.LastRun
        SourceRows = $g.Count
        P          = (ConvertFrom-StatusLine -Text $pick.Output)
    }
}
$devices = @($devices)

# ---------- fleet reference builds: the two most common per Windows version among updated devices ----------
$ref = @{}
$updatedOs = @($devices | Where-Object { $_.P.Result -eq 'UPDATED' -and (Get-OsMajor $_.P.OS) })
foreach ($g in ($updatedOs | Group-Object -Property { Get-OsMajor $_.P.OS })) {
    $top = @($g.Group | Group-Object -Property { $_.P.OS } | Sort-Object Count -Descending | Select-Object -First 2)
    $floor = ($top | ForEach-Object { Get-OsUbr $_.Name } | Measure-Object -Minimum).Minimum
    $ref[$g.Name] = @{ Current = $top[0].Name; Floor = [int]$floor }
}

function Test-Behind {
    param($Os)
    $m = Get-OsMajor $Os; $u = Get-OsUbr $Os
    return ($null -ne $u -and $ref.ContainsKey($m) -and $u -lt $ref[$m].Floor)
}

function Get-PatchLevel {
    param($Os)
    $m = Get-OsMajor $Os; $u = Get-OsUbr $Os
    if (-not $m -or $null -eq $u) { return '' }
    if ($m -eq '19045') {
        if ($u -eq $Win10LastNonEsu) { return 'Win10: stopped at the Oct 2025 update (no ESU)' }
        if ($u -lt $Win10LastNonEsu) { return 'Win10: not patched since before Oct 2025' }
    }
    $eol = ''
    $info = $WinInfo[$m]
    if ($info -and $info.EndOfUpdates -and (Get-Date) -gt [datetime]$info.EndOfUpdates) { $eol = "$($info.Name): updates ended $($info.EndOfUpdates)" }
    $parts = @()
    if (Test-Behind $Os) { $parts += "Behind (fleet on $($ref[$m].Current))" }
    if ($eol) { $parts += $eol }
    if ($parts.Count -gt 0) { return $parts -join '; ' }
    if ($ref.ContainsKey($m)) { return 'Current' }
    return ''
}

# ---------- PC-maker status table ----------
if (-not (Test-Path -Path $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null }
$oemRows = @()
$oem = @{}
if (Test-Path -Path $OemStatusCsv) {
    $oemRows = @(Import-Csv -Path $OemStatusCsv)
    foreach ($r in $oemRows) { if ($r.Model) { $oem["$($r.Model)".Trim()] = $r } }
}

# ---------- classify ----------
$order = [ordered]@{
    'No fix path' = 1; 'Needs BIOS update' = 2; 'Blocked - check OEM' = 3; 'Restart' = 4
    'Windows 10 not patching' = 5; 'Behind on updates' = 6; 'Start the update' = 7; 'Virtual machines' = 8
    'Secure Boot off' = 9; 'Legacy BIOS' = 10; 'Investigate' = 11; 'No result yet' = 12; 'In progress' = 13; 'Updated' = 14
}
$policy = 'the Enable Secureboot Certificate Updates policy'

function Get-Verdict {
    param($P, [string]$OemState, $FixedIn, [string]$Model, [string]$PatchLevel)
    $reason = "$($P.Reason)"; $au = "$($P.AU)"; $conf = "$($P.Conf)"; $os = "$($P.OS)"
    $evt = ("$($P.LastEvt)" -split '@')[0]
    $certsInFw = ($P.KEK23 -eq 'Y' -and $P.DB23 -eq 'Y')
    $notQueued = ($au -in '0x0', '', '-')
    $m = Get-OsMajor $os; $u = Get-OsUbr $os

    if (-not $P.Result) { return 'No result yet', "The Remediation hasn't reported. Check the device is still active in Intune; ignore it if retired." }
    if ($P.Result -eq 'UPDATED') {
        if ($OemState -eq 'NoBiosPlanned') { return 'Updated', 'Do not reset Secure Boot keys to factory defaults in BIOS on this model - its defaults lack the 2023 certificates.' }
        return 'Updated', ''
    }
    if ($P.Result -eq 'N/A') {
        if ($reason -match 'Legacy') { return 'Legacy BIOS', 'Boots in legacy BIOS mode, so Secure Boot is unavailable. Convert with MBR2GPT and switch the firmware to UEFI, or replace the device.' }
        return 'Secure Boot off', "Turn Secure Boot on in the BIOS. Check first why it's off (vendor software, imaging, BIOS defaults), and suspend BitLocker before changing BIOS settings to avoid a recovery prompt."
    }
    if ($P.Result -in 'CHECK', 'ERROR', 'UNREADABLE') { return 'Investigate', $reason }

    # NOT UPDATED
    $reboot = ($reason -match '0x8007015E|\(event 1800\)|Restart needed') -or ($au -eq '0x4100')
    $known  = ($evt -eq '1802') -or ($reason -match 'known firmware issue') -or ($conf -match 'Temporarily Paused')
    $fw     = $known -or ($reason -match '\((?:event )?(?:1795|1803)\)') -or ($evt -in '1795', '1803') -or
              ($conf -match 'Not Supported') -or ($au -eq '0x4004' -and -not $reboot)

    if ($fw) {
        if ($known)                                      { $why = 'Microsoft has paused the update on this model for a known firmware issue (event 1802); it may resume on its own' }
        elseif ($reason -match '1803' -or $evt -eq '1803') { $why = 'No PC-maker-signed KEK for this model (event 1803)' }
        elseif ($reason -match '1795' -or $evt -eq '1795') { $why = 'The firmware rejected the update (event 1795)' }
        elseif ($conf -match 'Not Supported')            { $why = 'Microsoft lists this hardware as not supported for the automatic update' }
        else                                             { $why = 'Stuck on the KEK step (AvailableUpdates 0x4004)' }
        switch ($OemState) {
            'NoBiosPlanned' { return 'No fix path', "$why. The PC maker has no BIOS update planned: replace or document as an exception." }
            'BiosAvailable' {
                if ($FixedIn) { return 'Needs BIOS update', "$why. Install BIOS $FixedIn or later, then restart twice." }
                return 'Needs BIOS update', "$why. Install the PC maker's BIOS update with the 2023 certificates, then restart twice."
            }
            default { return 'Blocked - check OEM', "$why. Look up this model with the PC maker and record it in oem-model-status.csv." }
        }
    }

    $behindNote = ''
    if ($PatchLevel -match '^Behind') { $behindNote = " Also behind on Windows updates ($PatchLevel)." }

    if ($reboot -or $reason -match 'BitLocker|1796|Update error|Update failed') {
        if ($reason -match 'BitLocker') { return 'Restart', ('Suspend BitLocker for 2 restarts (manage-bde -protectors -disable C: -rebootcount 2), then restart twice.' + $behindNote) }
        if ($au -eq '0x4004') { return 'Restart', ("Restart (twice if needed): only the KEK step is left and Windows reported 'reboot required'. If it's still at 0x4004 afterwards, the firmware is blocking it - check the PC maker." + $behindNote) }
        if (-not $reboot) { return 'Restart', ('Restart and recheck; if it keeps failing, check for a BIOS update.' + $behindNote) }
        if ($notQueued) { return 'Restart', ("Restart, then recheck. A restart is pending, but the certificate update itself hasn't started; if it still shows not started, add the device to $policy." + $behindNote) }
        return 'Restart', ('Restart. Windows is waiting on a reboot to continue the certificate update.' + $behindNote)
    }

    if ($Model -match $VmPattern) {
        if ($certsInFw) { $text = "The VM firmware already has the 2023 certificates; only the 2023-signed boot manager is missing because nothing started the update. Test $policy on one VM, then roll it out. For pooled hosts (such as Azure Virtual Desktop), update the golden image too." }
        else { $text = "The VM's firmware comes from the hypervisor or cloud platform. Start the update with $policy on a test VM first; if it reports event 1795 or 1803, the fix is on the host side." }
        if ($behindNote) { $text += " Also behind on Windows updates ($PatchLevel), so patch or rebuild the image." }
        return 'Virtual machines', $text
    }

    if ($m -eq '19045' -and $null -ne $u -and $u -le $Win10LastNonEsu) {
        if ($u -eq $Win10LastNonEsu) { return 'Windows 10 not patching', "Windows 10 stopped at the October 2025 update (19045.6456, the last one without ESU). Upgrade to Windows 11 if the hardware supports it, otherwise enroll in ESU (or replace); the certificate update can't run until it's patching again." }
        return 'Windows 10 not patching', "Windows 10 hasn't been patched since before October 2025 ($os). Upgrade to Windows 11 if the hardware supports it, otherwise fix patching and enroll in ESU (or replace)."
    }

    $noData = $reason -match 'No Secure Boot servicing data'
    if ($noData -or (Test-Behind $os) -or $m -eq '22621') {
        $cur = ''
        if ($ref.ContainsKey($m)) { $cur = $ref[$m].Current }
        if ($m -eq '19045') { return 'Windows 10 not patching', "Install the latest Windows 10 ESU update$(if ($cur) { " (fleet: $cur)" }), then recheck." }
        if ($m -eq '22621') { $text = 'Windows 11 22H2 is no longer serviced. Upgrade to a supported version of Windows 11; the certificate update can then run.' }
        elseif ($cur) { $text = "On $os; most of the fleet is on $cur. Fix Windows Update on this device; the certificate update runs once it's current." }
        else { $text = 'No Secure Boot servicing data. Install the latest cumulative update, then recheck.' }
        if ($certsInFw) { $text += " Its firmware already has the 2023 certificates, so once it's patched only the boot manager is left." }
        return 'Behind on updates', $text
    }

    if ($reason -match 'scheduled task is (Disabled|Missing)') { return 'Start the update', 'Re-enable the Secure-Boot-Update scheduled task (Enable-SecureBootUpdateTask.ps1 in %SystemRoot%\SecureBoot\ExampleRolloutScripts), then recheck.' }
    if ($certsInFw -and $notQueued) { return 'Start the update', "The firmware already has the 2023 certificates; nothing has started the update, so only the 2023-signed boot manager is left. Add the device to $policy, then restart." }
    if ($notQueued -or $reason -match 'nothing has triggered') { return 'Start the update', "Windows hasn't started the certificate update on this device. Add it to $policy (pilot by model first)." }
    return 'In progress', 'The update is queued or running; the Secure-Boot-Update task runs at startup and every 12 hours. Recheck after a restart or two.'
}

$report = foreach ($d in $devices) {
    $p = $d.P
    $model = "$($p.Model)".Trim()
    $oemRow = $null
    if ($model -and $oem.ContainsKey($model)) { $oemRow = $oem[$model] }
    $oemState = Get-OemState -Row $oemRow
    $fixedIn = $null
    if ($oemRow) { $fixedIn = $oemRow.FixedInBios }
    $patch = Get-PatchLevel $p.OS
    $verdict = Get-Verdict -P $p -OemState $oemState -FixedIn $fixedIn -Model $model -PatchLevel $patch
    $cat = $verdict[0]; $action = $verdict[1]
    if ($VendorPattern -and ("$($d.DeviceName)" -match $VendorPattern -or "$($d.Users)" -match $VendorPattern) -and $cat -ne 'Updated') {
        $action = ("$action Matches -VendorPattern (likely vendor-managed): check with the vendor before changing it.").Trim()
    }
    $m = Get-OsMajor $p.OS
    $win = ''
    if ($WinInfo.ContainsKey($m)) { $win = $WinInfo[$m].Name } elseif ($m) { $win = "build $m" }

    [pscustomobject]@{
        DeviceName       = $d.DeviceName
        Users            = $d.Users
        Category         = $cat
        Action           = $action
        PatchLevel       = $patch
        Windows          = $win
        Model            = $model
        BIOS             = $p.BIOS
        OS               = $p.OS
        Result           = $p.Result
        Reason           = $p.Reason
        Confidence       = $p.Conf
        AvailableUpdates = $p.AU
        KEK2023          = $p.KEK23
        DB2023           = $p.DB23
        LastEvent        = $p.LastEvt
        OemStatus        = $oemState
        FixedInBios      = $fixedIn
        LastRun          = $d.LastRun
        Serial           = $d.Serial
        SourceRows       = $d.SourceRows
        SortKey          = $order[$cat]
    }
}
$report = @($report | Sort-Object SortKey, Model, DeviceName)

# ---------- add newly blocked models to the PC-maker table ----------
$blockedCats = 'No fix path', 'Needs BIOS update', 'Blocked - check OEM'
$blockedModels = @($report | Where-Object { $_.Category -in $blockedCats -and $_.Model } | Select-Object -ExpandProperty Model -Unique)
$newOem = @(foreach ($mdl in $blockedModels) {
    if (-not $oem.ContainsKey($mdl)) { [pscustomobject]@{ Model = $mdl; OemStatus = ''; FixedInBios = ''; Notes = ''; LookUpAt = (Get-OemLink -Model $mdl) } }
})
if ($newOem.Count -gt 0) {
    $cols = New-Object System.Collections.Generic.List[string]
    foreach ($c in @('Model', 'OemStatus', 'FixedInBios', 'Notes', 'LookUpAt')) { $cols.Add($c) }
    if ($oemRows.Count -gt 0) { foreach ($c in $oemRows[0].PSObject.Properties.Name) { if (-not $cols.Contains($c)) { $cols.Add($c) } } }
    @($oemRows) + $newOem | Select-Object -Property $cols.ToArray() | Export-Csv -Path $OemStatusCsv -NoTypeInformation -Encoding $csvEncoding
}

# ---------- write files ----------
$stamp      = Get-Date -Format 'yyyy-MM-dd_HHmm'
$allFile    = Join-Path $OutputFolder "SecureBoot2023-AllDevices-$stamp.csv"
$actFile    = Join-Path $OutputFolder "SecureBoot2023-ActionList-$stamp.csv"
$noFixFile  = Join-Path $OutputFolder "SecureBoot2023-FirmwareBlocked-$stamp.csv"
$modelsFile = Join-Path $OutputFolder "SecureBoot2023-Models-$stamp.csv"

$deviceCols = 'DeviceName', 'Users', 'Category', 'Action', 'PatchLevel', 'Windows', 'Model', 'BIOS', 'OS', 'Result', 'Reason', 'Confidence',
              'AvailableUpdates', 'KEK2023', 'DB2023', 'LastEvent', 'OemStatus', 'FixedInBios', 'LastRun', 'Serial', 'SourceRows'
$report | Select-Object -Property $deviceCols | Export-Csv -Path $allFile -NoTypeInformation -Encoding $csvEncoding
$todo = @($report | Where-Object { $_.Category -ne 'Updated' })
if ($todo.Count -gt 0) { $todo | Select-Object -Property $deviceCols | Export-Csv -Path $actFile -NoTypeInformation -Encoding $csvEncoding }
$blocked = @($report | Where-Object { $_.Category -in $blockedCats })
if ($blocked.Count -gt 0) { $blocked | Select-Object -Property $deviceCols | Export-Csv -Path $noFixFile -NoTypeInformation -Encoding $csvEncoding }

$models = foreach ($g in ($report | Group-Object -Property Model)) {
    $d = $g.Group
    [pscustomobject]@{
        Model            = $g.Name
        Devices          = $d.Count
        Updated          = @($d | Where-Object Category -eq 'Updated').Count
        NeedsAction      = @($d | Where-Object Category -ne 'Updated').Count
        FirmwareBlocked  = @($d | Where-Object { $_.Category -in $blockedCats }).Count
        OemStatus        = ($d | Select-Object -First 1).OemStatus
        BiosVersionsSeen = (@($d | Where-Object { $_.BIOS } | Select-Object -ExpandProperty BIOS -Unique) | Select-Object -First 6) -join '; '
    }
}
$models | Sort-Object @{ Expression = 'FirmwareBlocked'; Descending = $true }, @{ Expression = 'NeedsAction'; Descending = $true }, @{ Expression = 'Devices'; Descending = $true } |
    Export-Csv -Path $modelsFile -NoTypeInformation -Encoding $csvEncoding

# ---------- summary ----------
Write-Host ''
if ($rows.Count -ne $report.Count) {
    Write-Host ("Secure Boot 2023 report - {0} devices ({1} rows; shared PCs report once per signed-in user)" -f $report.Count, $rows.Count)
} else {
    Write-Host ("Secure Boot 2023 report - {0} devices" -f $report.Count)
}
foreach ($name in $order.Keys) {
    Write-Host ("  {0,-24} {1,6}" -f $name, @($report | Where-Object Category -eq $name).Count)
}
Write-Host ("  {0,-24} {1,6}" -f 'Needs action (total)', $todo.Count)
$unknownModels = @($report | Where-Object { $_.Category -eq 'Blocked - check OEM' -and $_.Model } | Select-Object -ExpandProperty Model -Unique)
Write-Host ''
Write-Host "All devices:        $allFile"
if ($todo.Count -gt 0) { Write-Host "Action list:        $actFile" }
if ($blocked.Count -gt 0) { Write-Host "Firmware-blocked:   $noFixFile" }
Write-Host "By model:           $modelsFile"
if ($newOem.Count -gt 0) { Write-Host ("PC-maker table:     {0}  ({1} model(s) added)" -f $OemStatusCsv, $newOem.Count) }
if ($unknownModels.Count -gt 0) {
    Write-Host ''
    Write-Host ("Next: set OemStatus for {0} model(s) in {1}, then run this again." -f $unknownModels.Count, $OemStatusCsv)
}

if ($PassThru) { $report | Select-Object -Property $deviceCols }
