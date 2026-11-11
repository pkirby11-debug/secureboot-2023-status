# Secure Boot 2023 certificate status check

A read-only PowerShell check that reports whether a Windows PC has finished the
2023 Secure Boot certificate update:

- KEK: Microsoft Corporation KEK 2K CA 2023
- DB: Windows UEFI CA 2023
- DB: Microsoft UEFI CA 2023 and Microsoft Option ROM UEFI CA 2023 (only where the
  2011 third-party CA was trusted)
- Boot manager signed by Windows UEFI CA 2023

The 2011 Microsoft Secure Boot certificates expired in June and October 2026.
PCs without the 2023 certificates still boot, but they can't receive new
boot-level security fixes (boot manager, DBX revocations).

## What it checks

| Source | Values |
|---|---|
| Registry `HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing` | `UEFICA2023Status` (`Updated` = done), `UEFICA2023Error`, `ConfidenceLevel` |
| Registry `HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot` | `AvailableUpdates` (`0x4000` = every step finished) |
| System event log, source TPM-WMI | 1808 done, 1801 not applied, 1795/1796 errors, 1800 restart needed, 1802 known firmware issue, 1803 no OEM-signed KEK, 1032 BitLocker |
| Firmware | KEK and DB contents, read with `Get-SecureBootUEFI` |
| Scheduled task | `\Microsoft\Windows\PI\Secure-Boot-Update` must be enabled |
| Device | Manufacturer, model, BIOS version, OS build (for grouping results) |

It makes no changes. It must run elevated (SYSTEM through Intune or SCCM is fine).

## Output

One line per device:

```
NOT UPDATED: Blocked: no OEM-signed KEK for this model (1803) - check with the OEM | SB=On | Status=InProgress | AU=0x4004 | Err=- | KEK23=N DB23=Y 3P23=Y OROM23=Y | LastEvt=1803@2026-11-01 | Conf=Under Observation - More Data Needed | Task=Ready | OS=26100.7019 | Dell Inc. Latitude 5440 | BIOS 1.21.0
```

| Result | Meaning | Exit code |
|---|---|---|
| `UPDATED` | All required 2023 certificates and the 2023-signed boot manager are in place | 0 |
| `NOT UPDATED` | Not finished; the text after the colon says why | 1 |
| `CHECK` | Windows says Updated, but a 2023 certificate is missing from firmware (for example after a BIOS key reset) | 1 |
| `N/A` | Secure Boot is off, or the PC uses legacy BIOS | 0 |

Run with `-Detailed` to get a full object instead (desk-side checks, `Export-Csv`).

## Deploy

### Intune Remediations (detection only)

Devices > Manage devices > Scripts and remediations > Create

- Detection script: `Get-SecureBoot2023Status.ps1`
- Remediation script: none
- Run this script using the logged-on credentials: **No**
- Enforce script signature check: **No**
- Run script in 64-bit PowerShell: **Yes**
- Schedule: **Daily**

To read results, open the package > Device status, add the
**Pre-remediation detection output** column, and export. Split the output
on `|` to group by model and BIOS version.

Requires Windows Enterprise E3/E5 (included in Microsoft 365 E3/E5/F3). Devices
must be Entra joined or hybrid joined, and Intune-enrolled or co-managed.

### SCCM Run Scripts

Software Library > Scripts > Create Script, approve it, then right-click a
collection > Run Script. Results are grouped by exit code and output.

### Desk-side

```powershell
.\Get-SecureBoot2023Status.ps1 -Detailed
```

## Reporting only

This script does not trigger the update. To deploy the certificates, use the
Intune Settings catalog policy **Enable Secureboot Certificate Updates** (or the
matching Group Policy), piloted one model at a time. Devices that report 1795,
1802, 1803, or `AvailableUpdates = 0x4004` usually need a BIOS update from the
PC maker.

## Report: what to do with each device

`Get-SecureBoot2023Report.ps1` runs on an admin workstation (not as a
Remediation). It reads every device's detection output from the Remediation,
through Microsoft Graph or a Device status CSV export, keeps one row per device,
and puts each device in one category:

| Category | Meaning |
|---|---|
| No fix path | Firmware-blocked, and the PC maker has no BIOS update planned. Replace, or document as an exception. |
| Needs BIOS update | Firmware-blocked, and a BIOS with the 2023 certificates exists. |
| Blocked - check OEM | Firmware-blocked; the model hasn't been looked up yet. |
| Restart | Windows is waiting on a reboot (`0x4100`, event 1800, or error `0x8007015E` "reboot required"). |
| Windows 10 not patching | Stuck at 19045.6456 (October 2025, the last update without ESU) or earlier. Upgrade, enroll in ESU, or replace. |
| Behind on updates | Older build than most of the fleet, or no Secure Boot servicing data. Fix patching first. |
| Start the update | Patched, but nothing has started the update. Add it to the Enable Secureboot Certificate Updates policy. |
| Virtual machines | VMs that haven't finished. For pooled hosts such as Azure Virtual Desktop, fix the golden image. |
| Secure Boot off / Legacy BIOS | The certificates don't apply until Secure Boot can be turned on. |
| Investigate / No result yet / In progress / Updated | As named. |

Firmware-blocked means event 1803, 1795 or 1802, `AvailableUpdates` stuck at
`0x4004` without a pending reboot, or confidence "Not Supported - Known
Limitation" / "Temporarily Paused".

A Remediation assigned to user groups records one row per signed-in user, so
shared PCs repeat in the export. The report keeps one row per device name (the
newest result wins) and lists every user on it. Assigning the Remediation to a
device group gives one row per device at the source.

The `PatchLevel` column compares each device's build with the two most common
builds for its Windows version among updated devices in the same data, so
"behind" is measured against your own fleet. It also notes Windows versions whose
Enterprise updates have ended (for example Windows 11 23H2 after November 10, 2026).

A device can't report whether its maker plans a BIOS update, so that comes from
`oem-model-status.csv`. The first run creates it with each firmware-blocked model
and a link to that maker's Secure Boot page. Set `OemStatus` to `NoBiosPlanned`
or `BiosAvailable` (with the version in `FixedInBios`), then run the report
again. Later runs add newly seen models without touching your entries.

"No BIOS planned" alone doesn't mean a PC can't get the certificates. Windows
Update can still install them on many of those models (see Dell KB 000378734),
so only devices that are also firmware-blocked land in "No fix path".

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
.\Get-SecureBoot2023Report.ps1 -RemediationName '<your Remediation name>'
# or, with no Graph permissions, from an export of the Remediation's Device status page:
.\Get-SecureBoot2023Report.ps1 -InputCsv .\DeviceStatus.csv
```

Graph mode uses the delegated, read-only permissions
`DeviceManagementScripts.Read.All` and `DeviceManagementManagedDevices.Read.All`.

Optional: `-VendorPattern` takes a regular expression for vendor-managed systems
(for example medical imaging workstations), matched against device names and
users. Matching devices get a note to check with the vendor before changing them.

Output (in `.\SecureBoot2023-Report`):

- `SecureBoot2023-AllDevices-*.csv` - every device, with Category, Action and PatchLevel
- `SecureBoot2023-ActionList-*.csv` - every device that isn't Updated
- `SecureBoot2023-FirmwareBlocked-*.csv` - the service desk list (first three categories)
- `SecureBoot2023-Models-*.csv` - counts by model, for BIOS lookups and refresh planning

Run it on the CSV exactly as Intune exports it. Re-saving the CSV in Excel
changes timestamps and can trim trailing zeros from numbers.

## Testing

The detection script was tested against 24 simulated scenarios (PowerShell 7 with
the Windows cmdlets mocked). The report was tested with 54 checks: the category,
action and patch level for 39 device patterns (including ones seen in a real
fleet export), one-row-per-device merging, the PC-maker table across repeated
runs, Intune's export column names, and Graph paging with mocked Graph cmdlets.
Its categories were also compared device by device against a manual review of a
large real-world export, and all matched. Both scripts pass the
PSScriptAnalyzer syntax check for Windows PowerShell 5.1. Try them on devices
whose state you already know before a broad rollout.

## References

- [KB5068202 - Registry key updates for Secure Boot](https://support.microsoft.com/help/5068202)
- [KB5016061 - Secure Boot DB and DBX variable update events](https://support.microsoft.com/en-us/topic/secure-boot-db-and-dbx-variable-update-events-37e47cf8-608b-4a87-8175-bdead630eb69)
- [KB5085046 - Secure Boot troubleshooting guide](https://support.microsoft.com/en-us/kb/5085046)
- [KB5084567 - Sample Secure Boot E2E automation guide](https://support.microsoft.com/en-us/kb/5084567)
- [Secure Boot status report in Windows Autopatch](https://learn.microsoft.com/windows/deployment/windows-autopatch/monitor/secure-boot-status-report)
- [Intune Remediations](https://learn.microsoft.com/intune/device-management/tools/deploy-remediations)
- [Policy CSP - SecureBoot](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-secureboot)
