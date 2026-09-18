# PCMigration Reconciliation v4.0.0

PCMigration Reconciliation is a conservative Windows migration auditing and selective-repair toolkit. It captures independent evidence from a source and destination PC, explains what did not migrate, creates an inert repair plan, applies only individually approved and source-authorized actions, and preserves rollback evidence before mutation.

It is designed for experienced Windows users, administrators, technicians, and migration reviewers who want a transparent alternative to blindly copying profiles, registry hives, application databases, or credentials.

## Release summary

Version 4.0.0 consolidates the complete v3.2.1 package, the v3.3 native registry-backup revision, the PowerShell 5.1 HTML hotfix, and the final shortcut/Unicode corrections into one coherent distribution. Captures from older schemas are intentionally not accepted.

Most importantly, Windows shortcut files are no longer declared different merely because their opaque `.lnk` binary metadata differs. The comparison now uses normalized launch target, arguments, and working directory. A shortcut already present and functionally equivalent is listed in `Shortcut-Reconciliation.csv`, but is excluded from `Repair-Plan.csv` even if the raw files have different hashes.

## Included files

| File | Purpose |
|---|---|
| `Test-PCMigrationPackage-v4.0.0.ps1` | Parses scripts, verifies every packaged checksum, and runs regression tests. |
| `Capture-PCMigrationState-v4.0.0.ps1` | Captures applications, settings, registry state, shortcuts, Windows state, integration state, development tools, and manual/secure migration items. |
| `Compare-PCMigrationState-v4.0.0.ps1` | Validates both captures and generates reconciliation reports plus an inert repair plan. It never changes the destination. |
| `Invoke-PCMigrationRepair-v4.0.0.ps1` | Previews or applies individually approved, source-authorized repairs and creates backups before mutation. |
| `Verify-PCMigrationState-v4.0.0.ps1` | Recaptures the destination and repeats the comparison after repair. |
| `Rollback-PCMigrationRepair-v4.0.0.ps1` | Previews or restores file and narrow registry changes from a repair backup. |
| `PCMigration.Common-v4.0.0.ps1` | Shared PowerShell 5.1 and .NET implementation. Do not run directly. |
| `RegistryBackup-v4.0.0.ps1` | Optional native binary registry safety snapshots plus narrow targeted exports. Do not run directly. |
| `PCMigration-Reconciliation-v4.0.0-Guide.pdf` | Complete operational instructions and review guidance. |
| `CAPABILITIES-AND-LIMITATIONS.md` | Supported cases, special fixes, exclusions, and limitations. |
| `SHA256SUMS.txt` | Package integrity manifest. |

## Requirements

- Windows 10 or Windows 11.
- 64-bit Windows PowerShell 5.1. PowerShell 7 is not the supported execution host.
- The same migrated user should run the source and destination captures.
- Elevation is recommended for machine-wide coverage and required for administrative repairs and broad registry safety snapshots.
- Use a trusted, access-controlled drive. Captures contain detailed system and application metadata; optional registry snapshots are especially sensitive.
- Extract the release into its own clean folder. By default, unrelated files produce warnings; use `-StrictPackageContents` to reject them.

## Safe operating model

1. Capture broadly enough to establish evidence.
2. Compare offline without changing either PC.
3. Install applications before restoring their settings.
4. Review shortcut reconciliation before approving any shortcut copy.
5. Approve individual actions only.
6. Preview with the same authorization switches that will be used for application.
7. Apply, sign out, verify, and retain the rollback folder.

Every generated `Repair-Plan.csv` begins with `Approved=NO`. Neither `-AllowHighRisk` nor `-AllowAdminChanges` approves a row; those switches only authorize already approved rows.

# Complete workflow

Run all toolkit scripts from the extracted package directory in elevated 64-bit Windows PowerShell 5.1 unless a step explicitly says otherwise.

## 1. Validate the clean package

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
Get-ChildItem -LiteralPath $PWD -Filter '*.ps1' | Unblock-File
.\Test-PCMigrationPackage-v4.0.0.ps1
```

Expected result:

```text
Package validation passed: PowerShell parser, SHA256 manifest, and v4.0.0 regression checks.
```

Unrelated files are warnings by default. To require an exact package-only directory:

```powershell
.\Test-PCMigrationPackage-v4.0.0.ps1 -StrictPackageContents
```

Do not continue if a parser, missing-file, or hash failure is reported.

## 2. Capture the source PC

Close applications whose settings matter. The practical default is:

```powershell
.\Capture-PCMigrationState-v4.0.0.ps1 `
    -OutputPath 'P:\PCMigration-Source-v4.0.0' `
    -InventoryMode Standard `
    -CaptureSettingsPayload `
    -SearchSecureFileCandidates `
    -StartStoppedInventoryServices
```

If portable applications exist outside the usual locations:

```powershell
    -AdditionalPortableRoots 'D:\Tools','C:\Utilities','C:\PortableApps'
```

Optional comprehensive registry safety backup:

```powershell
.\Capture-PCMigrationState-v4.0.0.ps1 `
    -OutputPath 'P:\PCMigration-Source-v4.0.0' `
    -InventoryMode Standard `
    -CaptureSettingsPayload `
    -SearchSecureFileCandidates `
    -StartStoppedInventoryServices `
    -CaptureRegistrySafetyBackup
```

This adds native `HKCU\Software` and `HKLM\SOFTWARE` binary snapshots. They are forensic safety archives only, are never repair payloads, and must never be restored wholesale to another PC. Store the capture on encrypted, access-controlled media.

To obtain only the narrow targeted registry exports without the binary snapshots:

```powershell
    -CaptureRegistrySafetyBackup -RegistryBackupTargetedOnly
```

If a verified third-party application service owns a legitimate settings database, it can be stopped only during file capture and automatically restarted:

```powershell
    -QuiesceServiceName 'ExactVerifiedServiceName'
```

Never guess a service name. Security, Defender, Kaspersky, firewall, networking, credential, Search, AppX, VSS, installer, and core Windows services are denylisted.

## 3. Review the source capture

```powershell
Import-Csv 'P:\PCMigration-Source-v4.0.0\Capture-Status.csv' |
    Format-Table Collector,Status,Records,ElapsedSeconds,Message -AutoSize -Wrap
```

Investigate every `Failed` result. A `Partial` collector creates a comparison blind spot and is never interpreted as proof that an item is absent.

Review all captured shortcuts with useful relative locations:

```powershell
Import-Csv 'P:\PCMigration-Source-v4.0.0\Applications\Shortcuts.csv' |
    Sort-Object RelativeLocation |
    Format-Table RelativeLocation,TargetPath,Arguments,TargetExists -AutoSize -Wrap
```

## 4. Capture the destination before repair

Run as the migrated user, preferably elevated:

```powershell
.\Capture-PCMigrationState-v4.0.0.ps1 `
    -OutputPath 'C:\MigrationAudit\Destination-Before-v4.0.0' `
    -InventoryMode Standard `
    -SearchSecureFileCandidates `
    -StartStoppedInventoryServices
```

Do not use `-CaptureSettingsPayload` or `-CaptureRegistrySafetyBackup` on the destination.

## 5. Compare source and destination

```powershell
.\Compare-PCMigrationState-v4.0.0.ps1 `
    -SourceCapture 'P:\PCMigration-Source-v4.0.0' `
    -DestinationCapture 'C:\MigrationAudit\Destination-Before-v4.0.0' `
    -OutputPath 'C:\MigrationAudit\Reconciliation-Before-v4.0.0'
```

Open the HTML summary:

```powershell
Start-Process 'C:\MigrationAudit\Reconciliation-Before-v4.0.0\Summary.html'
```

Review in this order:

1. `Capture-Coverage.csv`
2. `Regression-Checks.csv`
3. `Shortcut-Reconciliation.csv`
4. `Shortcut-Gaps.csv`
5. `Likely-Migration-Gaps.csv`
6. `Missing-Applications.csv`
7. `Application-Settings-Gaps.csv`
8. `Windows-State-Gaps.csv`
9. `Manual-Secure-Actions.csv`
10. `Repair-Plan.csv`

## 6. Confirm shortcut results before any repair approval

Show every shortcut and its logical destination result:

```powershell
Import-Csv 'C:\MigrationAudit\Reconciliation-Before-v4.0.0\Shortcut-Reconciliation.csv' |
    Sort-Object FunctionalStatus,RelativeLocation |
    Format-Table RelativeLocation,DestinationPresent,FunctionalStatus,BinaryStatus,Risk,SourceTarget -AutoSize -Wrap
```

Show only real functional gaps:

```powershell
Import-Csv 'C:\MigrationAudit\Reconciliation-Before-v4.0.0\Shortcut-Gaps.csv' |
    Sort-Object RelativeLocation |
    Format-Table RelativeLocation,Status,DestinationPresent,TargetPath,Arguments -AutoSize -Wrap
```

`Shortcut-Equivalent-Binary-Differences.csv` is informational. Its rows were suppressed from the repair plan because the destination shortcut is already present and functionally equivalent. This is the expected location for shortcuts previously reported as high risk solely because the `.lnk` binary hashes differed.

## 7. Install missing applications first

Install required applications before restoring settings or shortcuts. Prefer compatible versions and vendor-supported installers. Exact source-correlated WinGet identities may appear as `WingetInstall` actions, but IDs and publishers must still be reviewed.

Never copy live credential stores, browser session databases, Keeper sessions, Windows Hello/DPAPI material, antivirus databases, Store repositories, or unknown application databases.

## 8. Recapture and compare after application installation

```powershell
.\Capture-PCMigrationState-v4.0.0.ps1 `
    -OutputPath 'C:\MigrationAudit\Destination-PostApps-v4.0.0' `
    -InventoryMode Standard `
    -SearchSecureFileCandidates `
    -StartStoppedInventoryServices

.\Compare-PCMigrationState-v4.0.0.ps1 `
    -SourceCapture 'P:\PCMigration-Source-v4.0.0' `
    -DestinationCapture 'C:\MigrationAudit\Destination-PostApps-v4.0.0' `
    -OutputPath 'C:\MigrationAudit\Reconciliation-PostApps-v4.0.0'
```

Use the new post-application `Shortcut-Reconciliation.csv` and `Repair-Plan.csv`. Do not reuse or merge an earlier plan.

## 9. Approve selected actions

```powershell
$PlanPath = 'C:\MigrationAudit\Reconciliation-PostApps-v4.0.0\Repair-Plan.csv'
$Plan = Import-Csv -LiteralPath $PlanPath

$Plan |
    Sort-Object {[int]$_.Priority},Risk,Method,Item |
    Format-Table ActionId,Approved,Priority,Method,Risk,RequiresAdmin,Item -AutoSize -Wrap
```

After reviewing specific action IDs:

```powershell
$ApprovedActionIds = @('A00012','A00018')

foreach($Row in $Plan){
    $Row.Approved = if($Row.ActionId -in $ApprovedActionIds){'YES'}else{'NO'}
}

$Plan | Export-Csv -LiteralPath $PlanPath -NoTypeInformation -Encoding UTF8
```

Edit only the `Approved` column. Do not change method, identity, artifact, destination, package, feature, capability, or hash fields.

## 10. Preview the approved repair

Low/medium current-user actions:

```powershell
.\Invoke-PCMigrationRepair-v4.0.0.ps1 `
    -SourceCapture 'P:\PCMigration-Source-v4.0.0' `
    -PlanPath $PlanPath
```

If approved rows include high-risk or administrative actions, preview with the same gates required for application:

```powershell
.\Invoke-PCMigrationRepair-v4.0.0.ps1 `
    -SourceCapture 'P:\PCMigration-Source-v4.0.0' `
    -PlanPath $PlanPath `
    -AllowHighRisk `
    -AllowAdminChanges
```

Preview mode makes no destination changes.

## 11. Apply the reviewed repair

```powershell
.\Invoke-PCMigrationRepair-v4.0.0.ps1 `
    -SourceCapture 'P:\PCMigration-Source-v4.0.0' `
    -PlanPath $PlanPath `
    -AllowHighRisk `
    -AllowAdminChanges `
    -Apply
```

The script records the exact backup folder on the destination desktop. Keep it until final verification and a stable operating period are complete.

## 12. Sign out and sign back in

This reloads Explorer, Console Host, regional/clock, font, language, personalization, and shell state. Restart Windows when a feature, capability, installer, or vendor application requires it.

## 13. Verify

```powershell
.\Verify-PCMigrationState-v4.0.0.ps1 `
    -SourceCapture 'P:\PCMigration-Source-v4.0.0' `
    -DestinationCapturePath 'C:\MigrationAudit\Destination-After-v4.0.0' `
    -ReportPath 'C:\MigrationAudit\Reconciliation-After-v4.0.0'
```

Review `Summary.html`, `Regression-Checks.csv`, `Capture-Coverage.csv`, `Shortcut-Reconciliation.csv`, `Likely-Migration-Gaps.csv`, and `Manual-Secure-Actions.csv`.

## 14. Roll back if necessary

Preview:

```powershell
.\Rollback-PCMigrationRepair-v4.0.0.ps1 `
    -BackupPath 'C:\Users\USER\Desktop\PCMigration-v4.0.0-Backup-YYYYMMDD-HHMMSS'
```

Apply:

```powershell
.\Rollback-PCMigrationRepair-v4.0.0.ps1 `
    -BackupPath 'C:\Users\USER\Desktop\PCMigration-v4.0.0-Backup-YYYYMMDD-HHMMSS' `
    -Apply
```

To remove registry subtrees that did not exist before repair, add `-RemoveNewRegistryKeys` only after reviewing the preview. Package installations, Windows features, and capabilities are recorded but are not automatically uninstalled.

## Unicode and special-path behavior

All package text, CSV, and JSON outputs use Unicode-safe APIs and UTF-8. Literal filesystem operations preserve the exact original path. Comparison normalization uses Unicode Form C only; compatibility characters are not collapsed. Therefore the legal Windows filename character `µ` (U+00B5 MICRO SIGN) survives capture, reporting, manifest hashing, payload copy, and repair authorization, while remaining distinct from `μ` (U+03BC GREEK SMALL LETTER MU). The validator contains a regression test for this behavior.

Reparse points are deliberately skipped, parent traversal is rejected, and repair destinations must resolve through an approved root token or shortcut root. The tool does not promise support for every legacy application that mishandles Unicode internally.

## Important limitations

- This is reconciliation and selective repair, not disk imaging, profile cloning, or a guarantee of identical PCs.
- Credentials, private keys, browser tokens, DPAPI state, Windows Hello, passkeys, EFS keys, protected Store data, and antivirus runtime databases are never generically migrated.
- Drivers, services, tasks, VPNs, printers, shares, firewall rules, ODBC DSNs, certificates with private keys, and licenses are primarily inventoried for deliberate/manual handling.
- Captures can contain personal and security-sensitive metadata. Optional binary registry snapshots are highly sensitive.
- A hash difference proves bytes differ; it does not prove the source should overwrite the destination.
- Applications should be installed before their settings are restored.
- Windows build, architecture, application-version, policy, domain, and hardware differences can make source settings inappropriate.
- Always maintain independent backups. Use at your own risk; no warranty is provided.

See `CAPABILITIES-AND-LIMITATIONS.md` and the PDF guide for the detailed support matrix and safety model.

## License

MIT License. See `LICENSE`.
