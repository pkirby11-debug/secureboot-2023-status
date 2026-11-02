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

## Report: devices with no fix path

`Get-SecureBoot2023Report.ps1` runs on an admin workstation (not as a
Remediation). It reads every device's detection output from the Remediation,
through Microsoft Graph or a Device status CSV export, and puts each device in
one category:

| Category | Meaning |
|---|---|
| No fix path | Firmware-blocked, and the PC maker has no BIOS update planned. Replace, or document as an exception. |
| Needs BIOS update | Firmware-blocked, and a BIOS with the 2023 certificates exists. |
| Blocked - check OEM | Firmware-blocked; the model hasn't been looked up yet. |
| IT action | Not finished, but no BIOS needed (trigger the policy, restart, patch, re-enable the task). |
| Investigate / No result yet / Updated / Not applicable | As named. |

Firmware-blocked means event 1803, 1795 or 1802, `AvailableUpdates` stuck at
`0x4004`, or confidence "Not Supported - Known Limitation" / "Temporarily Paused".

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
Output (in `.\SecureBoot2023-Report`): all devices, the firmware-blocked list for
the service desk, and a by-model summary.

## Testing

The detection script was tested against 24 simulated scenarios (PowerShell 7 with
the Windows cmdlets mocked). The report was tested with 37 checks covering CSV
input (including Intune's export column names), the PC-maker table across repeated
runs, and Graph paging with mocked Graph cmdlets. Both pass the PSScriptAnalyzer syntax check for Windows PowerShell 5.1.
Neither has run against a real tenant or PC yet. Try them on devices whose state
you already know before a broad rollout.

## References

- [KB5068202 - Registry key updates for Secure Boot](https://support.microsoft.com/help/5068202)
- [KB5016061 - Secure Boot DB and DBX variable update events](https://support.microsoft.com/en-us/topic/secure-boot-db-and-dbx-variable-update-events-37e47cf8-608b-4a87-8175-bdead630eb69)
- [KB5085046 - Secure Boot troubleshooting guide](https://support.microsoft.com/en-us/kb/5085046)
- [KB5084567 - Sample Secure Boot E2E automation guide](https://support.microsoft.com/en-us/kb/5084567)
- [Secure Boot status report in Windows Autopatch](https://learn.microsoft.com/windows/deployment/windows-autopatch/monitor/secure-boot-status-report)
- [Intune Remediations](https://learn.microsoft.com/intune/device-management/tools/deploy-remediations)
- [Policy CSP - SecureBoot](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-secureboot)
