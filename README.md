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

## Testing

Tested against 24 simulated scenarios (PowerShell 7 with the Windows cmdlets
mocked), and checked for Windows PowerShell 5.1 syntax compatibility with
PSScriptAnalyzer. Run it on a few PCs whose state you already know before a
broad rollout.

## References

- [KB5068202 - Registry key updates for Secure Boot](https://support.microsoft.com/help/5068202)
- [KB5016061 - Secure Boot DB and DBX variable update events](https://support.microsoft.com/en-us/topic/secure-boot-db-and-dbx-variable-update-events-37e47cf8-608b-4a87-8175-bdead630eb69)
- [KB5085046 - Secure Boot troubleshooting guide](https://support.microsoft.com/en-us/kb/5085046)
- [KB5084567 - Sample Secure Boot E2E automation guide](https://support.microsoft.com/en-us/kb/5084567)
- [Secure Boot status report in Windows Autopatch](https://learn.microsoft.com/windows/deployment/windows-autopatch/monitor/secure-boot-status-report)
- [Intune Remediations](https://learn.microsoft.com/intune/device-management/tools/deploy-remediations)
- [Policy CSP - SecureBoot](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-secureboot)
