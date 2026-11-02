<#
.SYNOPSIS
    Builds a Secure Boot 2023 certificate report from the Get-SecureBoot2023Status.ps1
    Intune Remediation results, and lists the devices that have no fix path.

.DESCRIPTION
    Reads each device's one-line detection output (from Microsoft Graph, or from a CSV
    export of the Remediation's Device status page) and puts every device in one category:

      No fix path          Firmware-blocked AND the PC maker has no BIOS update planned
                           for the model. Replace, or document as an exception.
      Needs BIOS update    Firmware-blocked, and the PC maker has a BIOS that fixes it.
      Blocked - check OEM  Firmware-blocked; the model's PC-maker status isn't recorded yet.
      IT action            Not finished, but no BIOS is needed (trigger, restart, patch).
      Investigate          CHECK or ERROR results, or output that couldn't be read.
      No result yet        The detection script hasn't reported for this device.
      Updated
      Not applicable       Secure Boot off, or legacy BIOS.

    Firmware-blocked = the detection output shows a signal Microsoft documents as needing
    the PC maker: event 1803 (no OEM-signed KEK), 1795 (firmware rejected the update),
    1802 (known firmware issue), AvailableUpdates stuck at 0x4004, or confidence level
    "Not Supported - Known Limitation" / "Temporarily Paused".

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

.PARAMETER PassThru
    Also return the per-device rows to the pipeline.

.EXAMPLE
    .\Get-SecureBoot2023Report.ps1
.EXAMPLE
    .\Get-SecureBoot2023Report.ps1 -RemediationName 'Secure Boot 2023 cert status'
.EXAMPLE
    .\Get-SecureBoot2023Report.ps1 -InputCsv .\DeviceStatus.csv

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

    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'
# UTF-8 with BOM so Excel shows accented names correctly (PowerShell 7 needs 'utf8BOM' for that)
$csvEncoding = 'UTF8'
if ($PSVersionTable.PSVersion.Major -ge 6) { $csvEncoding = 'utf8BOM' }
if (-not $OemStatusCsv) { $OemStatusCsv = Join-Path -Path $OutputFolder -ChildPath 'oem-model-status.csv' }

# ---------- where to look up each PC maker (from Microsoft's OEM directory) ----------
$OemDirectory = 'https://support.microsoft.com/en-us/topic/original-equipment-manufacturer-oem-pages-for-secure-boot-9ecc3ba4-fb50-4bd3-9e9b-f16b35b8fb68'

function Get-OemLink {
    param([string]$Model)
    switch -Regex ($Model) {
        'Virtual Machine|VMware|VirtualBox|KVM|QEMU|Xen|Parallels' { return 'Virtual machine: its firmware comes from the hypervisor or cloud platform, not a BIOS' }
        '^Dell'                         { return 'https://www.dell.com/support/kbdoc/000347876/microsoft-2011-secure-boot-certificate-expiration (no-BIOS-planned list: https://www.dell.com/support/kbdoc/000378734)' }
        '^(HP|Hewlett)'                 { return 'https://support.hp.com/document/ish_13070353-13070429-16' }
        '^Lenovo'                       { return 'https://support.lenovo.com/us/en/solutions/HT518129' }
        '^Microsoft Corporation Surface' { return 'https://support.microsoft.com/en-us/surface/surface-secure-boot-certificates-532abf3b-bafe-420f-b615-bf174105549e' }
        '^Panasonic'                    { return 'https://global-pc-support.connect.panasonic.com/info/in260205' }
        '^Acer'                         { return 'https://community.acer.com/kb/articles/18840-update-your-secure-boot-certificates-in-june-2026-to-stay-protected' }
        '^ASUS'                         { return 'https://www.asus.com/us/support/faq/1055903/' }
        default                         { return $OemDirectory }
    }
}

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

function Test-FirmwareBlocked {
    param($P)
    if ($P.Result -ne 'NOT UPDATED') { return $false }
    return ($P.Reason -match '\((?:event )?(?:1795|1802|1803)\)|known firmware issue|KEK step') -or
           ($P.AU -eq '0x4004') -or
           ($P.Conf -match 'Not Supported|Temporarily Paused')
}

function Get-ItAction {
    param($P)
    $r = "$($P.Reason)"
    if ($r -match 'scheduled task is (Disabled|Missing)') { return 'Re-enable the Secure-Boot-Update scheduled task (Enable-SecureBootUpdateTask.ps1 in %SystemRoot%\SecureBoot\ExampleRolloutScripts)' }
    if ($r -match 'BitLocker')                         { return 'Suspend BitLocker for 2 restarts (manage-bde -protectors -disable C: -rebootcount 2), then restart twice' }
    if ($r -match 'Restart needed')                    { return 'Restart the device' }
    if ($r -match 'No Secure Boot servicing data') {
        if ("$($P.OS)" -like '19045.*') { return 'Windows 10 22H2 without recent updates - enroll in ESU or upgrade to Windows 11, then install the latest cumulative update' }
        return 'Install the latest cumulative update'
    }
    if ($r -match 'nothing has triggered')             { return 'Add the device to the Enable Secureboot Certificate Updates policy (pilot by model first)' }
    if ($r -match 'Firmware already has')              { return 'Restart - only the 2023-signed boot manager is left to install' }
    if ($r -match 'In progress')                       { return 'No action - recheck after a restart or two' }
    if ($r -match '1796|Update error|Update failed')   { return 'Restart and recheck; if it keeps failing, check for an OEM BIOS update' }
    return 'Recheck after the next restart'
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

# ---------- PC-maker status table ----------
if (-not (Test-Path -Path $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null }
$oemRows = @()
$oem = @{}
if (Test-Path -Path $OemStatusCsv) {
    $oemRows = @(Import-Csv -Path $OemStatusCsv)
    foreach ($r in $oemRows) { if ($r.Model) { $oem["$($r.Model)".Trim()] = $r } }
}

# ---------- classify ----------
$order = @{ 'No fix path' = 1; 'Needs BIOS update' = 2; 'Blocked - check OEM' = 3; 'IT action' = 4; 'Investigate' = 5; 'No result yet' = 6; 'Updated' = 7; 'Not applicable' = 8 }

$report = foreach ($r in $rows) {
    $p = ConvertFrom-StatusLine -Text $r.Output
    $model = "$($p.Model)".Trim()
    $oemRow = $null
    if ($model -and $oem.ContainsKey($model)) { $oemRow = $oem[$model] }
    $oemState = Get-OemState -Row $oemRow
    $fixedIn = $null
    if ($oemRow) { $fixedIn = $oemRow.FixedInBios }

    if (-not $p.Result) {
        $cat = 'No result yet'; $action = 'Detection has not reported yet - check the device is online and getting Intune policy'
    }
    elseif ($p.Result -eq 'UPDATED') {
        $cat = 'Updated'; $action = ''
        if ($oemState -eq 'NoBiosPlanned') { $action = 'Do not reset Secure Boot keys to factory defaults in BIOS on this model - its defaults lack the 2023 certificates' }
    }
    elseif ($p.Result -eq 'N/A') {
        $cat = 'Not applicable'; $action = $p.Reason
    }
    elseif ($p.Result -in 'CHECK', 'ERROR', 'UNREADABLE') {
        $cat = 'Investigate'; $action = $p.Reason
    }
    elseif (Test-FirmwareBlocked -P $p) {
        $paused = ''
        if ($p.Conf -match 'Temporarily Paused' -or $p.Reason -match 'known firmware issue') { $paused = ' (Microsoft has paused this model for a known issue; it may resume on its own)' }
        switch ($oemState) {
            'NoBiosPlanned' { $cat = 'No fix path';       $action = 'Replace or document as an exception: Windows is blocked by the firmware and the PC maker has no BIOS update planned' + $paused }
            'BiosAvailable' {
                $cat = 'Needs BIOS update'
                $action = 'Install the PC maker''s BIOS update with the 2023 certificates, then restart twice'
                if ($fixedIn) { $action = "Install BIOS $fixedIn or later, then restart twice" }
                $action += $paused
            }
            default {
                $cat = 'Blocked - check OEM'
                $action = 'Look up this model with the PC maker and record it in oem-model-status.csv' + $paused
                if ($p.Conf -match 'Not Supported') { $action = 'Microsoft lists this hardware as not supported for the automatic update - check the PC maker for a BIOS; likely an exception' }
            }
        }
    }
    else {
        $cat = 'IT action'; $action = Get-ItAction -P $p
    }

    [pscustomobject]@{
        DeviceName       = $r.DeviceName
        User             = $r.User
        Category         = $cat
        Action           = $action
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
        LastRun          = $r.LastRun
        Serial           = $r.Serial
        SortKey          = $order[$cat]
    }
}
$report = @($report | Sort-Object SortKey, Model, DeviceName)

# ---------- add newly blocked models to the PC-maker table ----------
$blockedCats = 'No fix path', 'Needs BIOS update', 'Blocked - check OEM'
$blockedModels = @($report | Where-Object { $_.Category -in $blockedCats -and $_.Model } | Select-Object -ExpandProperty Model -Unique)
$newOem = @(foreach ($m in $blockedModels) {
    if (-not $oem.ContainsKey($m)) { [pscustomobject]@{ Model = $m; OemStatus = ''; FixedInBios = ''; Notes = ''; LookUpAt = (Get-OemLink -Model $m) } }
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
$noFixFile  = Join-Path $OutputFolder "SecureBoot2023-FirmwareBlocked-$stamp.csv"
$modelsFile = Join-Path $OutputFolder "SecureBoot2023-Models-$stamp.csv"

$deviceCols = 'DeviceName', 'User', 'Category', 'Action', 'Model', 'BIOS', 'OS', 'Result', 'Reason', 'Confidence', 'AvailableUpdates', 'KEK2023', 'DB2023', 'LastEvent', 'OemStatus', 'FixedInBios', 'LastRun', 'Serial'
$report | Select-Object -Property $deviceCols | Export-Csv -Path $allFile -NoTypeInformation -Encoding $csvEncoding
$blocked = @($report | Where-Object { $_.Category -in $blockedCats })
if ($blocked.Count -gt 0) { $blocked | Select-Object -Property $deviceCols | Export-Csv -Path $noFixFile -NoTypeInformation -Encoding $csvEncoding }

$models = foreach ($g in ($report | Group-Object -Property Model)) {
    $d = $g.Group
    [pscustomobject]@{
        Model              = $g.Name
        Devices            = $d.Count
        NoFixPath          = @($d | Where-Object Category -eq 'No fix path').Count
        NeedsBios          = @($d | Where-Object Category -eq 'Needs BIOS update').Count
        BlockedCheckOem    = @($d | Where-Object Category -eq 'Blocked - check OEM').Count
        ItAction           = @($d | Where-Object Category -eq 'IT action').Count
        Updated            = @($d | Where-Object Category -eq 'Updated').Count
        OemStatus          = ($d | Select-Object -First 1).OemStatus
        BiosVersionsSeen   = (@($d | Where-Object { $_.BIOS } | Select-Object -ExpandProperty BIOS -Unique) | Select-Object -First 6) -join '; '
    }
}
$models | Sort-Object @{ Expression = { $_.NoFixPath + $_.NeedsBios + $_.BlockedCheckOem }; Descending = $true }, @{ Expression = 'Devices'; Descending = $true } |
    Export-Csv -Path $modelsFile -NoTypeInformation -Encoding $csvEncoding

# ---------- summary ----------
Write-Host ''
Write-Host ("Secure Boot 2023 report - {0} devices" -f $report.Count)
foreach ($name in ($order.GetEnumerator() | Sort-Object Value | ForEach-Object { $_.Key })) {
    $n = @($report | Where-Object Category -eq $name).Count
    Write-Host ("  {0,-22} {1,6}" -f $name, $n)
}
$unknownModels = @($report | Where-Object { $_.Category -eq 'Blocked - check OEM' -and $_.Model } | Select-Object -ExpandProperty Model -Unique)
Write-Host ''
Write-Host "All devices:        $allFile"
if ($blocked.Count -gt 0) { Write-Host "Firmware-blocked:   $noFixFile" }
Write-Host "By model:           $modelsFile"
if ($newOem.Count -gt 0) { Write-Host ("PC-maker table:     {0}  ({1} model(s) added)" -f $OemStatusCsv, $newOem.Count) }
if ($unknownModels.Count -gt 0) {
    Write-Host ''
    Write-Host ("Next: set OemStatus for {0} model(s) in {1}, then run this again." -f $unknownModels.Count, $OemStatusCsv)
}

if ($PassThru) { $report | Select-Object -Property $deviceCols }
