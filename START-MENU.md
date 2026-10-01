# Windows 10 Start-menu capture and restoration

This module supplies the Start workflow omitted from v4.0.0. It is separate from the main reconciliation capture and repair plan. Run as the intended user in **64-bit Windows PowerShell 5.1**, in that user's interactive session. Windows 11 pins and Windows Server are excluded.

## Choose the right operation

| Need | Command | Capture/input |
|---|---|---|
| Audit or restore Start-menu shortcuts | Main capture/compare/repair workflow | Core schema 4.0 capture |
| Preserve Windows 10 pins for future migration | `Capture-StartMenu-v4.1.0.ps1` | Run on source; separate new folder |
| Inspect link/ID exports and unresolved tiles | `Diagnose-Build-StartLayout-v4.1.0.ps1` | Separate Start capture |
| Apply the exported XML layout | Diagnosis command with `-ApplyPolicy -Apply` | XML export; Windows edition/policy support required |
| Restore only the captured tile grid when XML omitted pins | `Restore-StartTileGrid-v4.1.0.ps1 -Apply` | Captured tile-grid registry export |

Start-menu shortcuts and pinned tiles are different state. Install applications and reconcile shortcuts first. A regular core capture, including its optional registry safety snapshots, is **not** an input for the Start restore command.

## 1. Capture the original source layout

Run this on the source while its desired layout is still present:

```powershell
.\Capture-StartMenu-v4.1.0.ps1 `
    -OutputPath 'P:\PCMigration-StartMenu-Source-v4.1.0'
```

Use a new, nonexistent directory. The capture contains:

- `Meta.json` and `Capture-Status.csv`.
- `StartLayout-Links.xml` and `StartLayout-IDs.xml`, if each export succeeds.
- `Get-StartApps.csv` and `StartMenu-Shortcuts.csv` with relative locations.
- Captured `.lnk` and `.url` files under `StartMenu\User` and `StartMenu\Common`.
- `CloudStore\CloudStore-KeyIndex.csv` and successfully exported `Key-###.reg` files for curated tile-grid keys only.
- `SHA256SUMS.txt` for all captured artifacts. Do not edit the capture.

Review `Capture-Status.csv`. XML export and CloudStore export are independent: an XML failure does not necessarily prevent tile-grid recovery. An XML success does not establish that all visible pins were exported. Compare both exports with the source layout. Exporting live state is not an atomic Windows snapshot.

The new module uses capture schema `StartMenu-1.0`. Trusted earlier `Capture-StartMenu-v2.5.4.ps1` captures remain accepted. Legacy captures lack a manifest and therefore produce a warning. Earlier reconciliation captures are not interchangeable with Start captures.

## 2. Prepare the destination

Install missing applications, run the main comparison, review `Shortcut-Reconciliation.csv`, and apply only the necessary approved shortcut actions. A functionally equivalent shortcut already on the destination needs no copy.

If you may apply an XML policy, preserve the destination's original Start layout first:

```powershell
.\Capture-StartMenu-v4.1.0.ps1 `
    -OutputPath 'C:\MigrationAudit\PCMigration-StartMenu-Destination-Before-v4.1.0'
```

The XML policy backup preserves the three policy values only; it does not preserve the previous tile grid. The binary fallback automatically creates its own grid-and-policy backup.

## 3. Diagnose before restoring

```powershell
.\Diagnose-Build-StartLayout-v4.1.0.ps1 `
    -CapturePath 'P:\PCMigration-StartMenu-Source-v4.1.0' `
    -OutputPath 'C:\MigrationAudit\StartReports-v4.1.0'
```

Use a new output directory. This writes reports; it does not change Start, copy shortcuts, or stop Explorer.

Open `StartTiles-Links-Diagnostics.csv` and `StartTiles-IDs-Diagnostics.csv`. Each row contains the group, tile type, relative shortcut location, destination link, link presence, application IDs, and identity resolution.

To investigate a particular missing app, add `-NameMatchPattern 'Blockstream|Green'`. This is a general regex filter, not a hardcoded application dependency. If a tile is absent from both XML exports despite being visible on the source, XML editing cannot recover its omitted pin.

Legacy captures do not record source profile roots. If they contain absolute old-user paths, review and resolve those through the main shortcut workflow. New captures record the source roots for destination-user path remapping.

## 4A. XML layout route

Build corrected XML and diagnose its destination identities:

```powershell
.\Diagnose-Build-StartLayout-v4.1.0.ps1 `
    -CapturePath 'P:\PCMigration-StartMenu-Source-v4.1.0' `
    -OutputPath 'C:\MigrationAudit\StartReports-XML-v4.1.0' `
    -BuildCorrectedLayout
```

This writes `StartLayout-Corrected.xml`. It remaps recorded source-user roots and updates links only when the destination file exists. It does not invent missing pins or stage/copy source shortcuts. Taskbar layout elements are omitted from this Start-only output. Use `-LayoutMode IDs` if the ID export better represents the desired source layout.

Preview policy installation (new report directory):

```powershell
.\Diagnose-Build-StartLayout-v4.1.0.ps1 `
    -CapturePath 'P:\PCMigration-StartMenu-Source-v4.1.0' `
    -OutputPath 'C:\MigrationAudit\StartReports-PolicyPreview-v4.1.0' `
    -ApplyPolicy
```

Apply after review (another new report directory):

```powershell
.\Diagnose-Build-StartLayout-v4.1.0.ps1 `
    -CapturePath 'P:\PCMigration-StartMenu-Source-v4.1.0' `
    -OutputPath 'C:\MigrationAudit\StartReports-PolicyApply-v4.1.0' `
    -ApplyPolicy `
    -Apply
```

This stores the XML under the user's LocalAppData and sets three current-user Explorer policy values: `LockedStartLayout`, `StartLayoutFile`, and `ReapplyStartLayoutEveryLogon`. It backs up the prior values, including absence and value type, on the user's actual Desktop folder.

**Sign out completely and sign back in.** A full layout policy locks customization while enabled. After checking the applied layout, preview clearing it:

```powershell
.\Diagnose-Build-StartLayout-v4.1.0.ps1 -RemovePolicy
```

Then clear it and sign out/in again:

```powershell
.\Diagnose-Build-StartLayout-v4.1.0.ps1 -RemovePolicy -Apply
```

Removal backs up the current policy first. It clears only those three values and does not restore the prior tile layout. Organization-managed policy may be reapplied; the module does not bypass it. XML policy support varies with Windows edition and configuration.

Policy rollback, using the exact printed policy backup:

```powershell
.\Diagnose-Build-StartLayout-v4.1.0.ps1 `
    -RollbackBackup 'C:\Users\USER\Desktop\PCMigration-StartPolicy-Backup-EXACT-FOLDER'

.\Diagnose-Build-StartLayout-v4.1.0.ps1 `
    -RollbackBackup 'C:\Users\USER\Desktop\PCMigration-StartPolicy-Backup-EXACT-FOLDER' `
    -Apply
```

Policy rollback restores policy values only. Keep the destination Start capture from step 2 if you may need its former tile grid. Policy XML files and report files remain as audit artifacts; rollback does not delete them.

## 4B. Tiles-only binary fallback

Use this route when XML export omitted actual source pins and you have a trusted tile-grid capture. This is an **unsupported, experimental Windows 10 binary-state operation**. It is not automatically scheduled in `Repair-Plan.csv`.

Preview:

```powershell
.\Restore-StartTileGrid-v4.1.0.ps1 `
    -CapturePath 'P:\PCMigration-StartMenu-Source-v4.1.0'
```

Apply:

```powershell
.\Restore-StartTileGrid-v4.1.0.ps1 `
    -CapturePath 'P:\PCMigration-StartMenu-Source-v4.1.0' `
    -Apply
```

For your existing legacy capture, substitute its real folder, for example `H:\PCMigration-StartMenu-v2.5.4`. You do not need to rerun a source capture if that trusted folder already contains `Meta.json`, the CloudStore index, and its successful tile-grid `.reg` export.

The command:

1. Verifies capture hashes when supplied and validates every registry header against exactly one curated tile-grid subtree.
2. Locates one destination tile-grid key and retains its dynamic identity/GUID, even if the source and destination identities already match.
3. Remaps registry header paths only. Binary/string value data is not rewritten.
4. Backs up the destination tile grid and the three Start policy values before mutation.
5. Stops shell processes in the current session, clears those policy values, replaces the selected grid, and immediately compares registry exports.
6. Attempts automatic grid-and-policy rollback if import or verification fails; restarts Explorer and removes temporary `.reg` staging in `finally`.

It does not copy shortcuts, restore taskbar pins, transplant `systempartitionindex`, replace unrelated CloudStore state, or install apps. Temporary `.reg` staging is required for the native registry import and lives under `%TEMP%`, outside the capture/package.

Different Windows build numbers are blocked by default. `-ForceDifferentBuild` is an explicit unsupported Windows 10 override; it never enables Windows 11. If no destination grid exists, pin one tile and sign out/in first. If multiple grids are listed, review them and supply `-DestinationTileGridChildName` rather than guessing.

## 5. Verify visually after sign-out/in

Check group names, tile order/size, missing pins, and application launches. A successful immediate registry comparison confirms imported state, not correct shell rendering or application identity resolution. The main verification command does not certify the tile layout.

Keep the exact backup folder printed by the tile script. It is independent from the core repair backup.

Preview tile rollback:

```powershell
.\Restore-StartTileGrid-v4.1.0.ps1 `
    -RollbackBackup 'C:\Users\USER\Desktop\PCMigration-StartTileGrid-Backup-EXACT-FOLDER'
```

Apply rollback and sign out/in:

```powershell
.\Restore-StartTileGrid-v4.1.0.ps1 `
    -RollbackBackup 'C:\Users\USER\Desktop\PCMigration-StartTileGrid-Backup-EXACT-FOLDER' `
    -Apply
```

Rollback requires the same user, computer, and Windows build and validates the backup manifest. New rollback does not consume older v2.5.6.1 backup folders; keep that older script with any existing old-format backups.

## Unicode fix and references

Start XML is read with an XML reader that honors its encoding declaration/BOM and prohibits DTDs. UTF-8 without a BOM therefore preserves `µ` (U+00B5) rather than producing `Âµ`. This is distinct from the core toolkit's exact Unicode filename handling. `µ` and `μ` (U+03BC) remain different characters.

Microsoft documents XML export/deployment and policy behavior; it does not document or support this binary CloudStore migration fallback:

- [Customize the Start layout](https://learn.microsoft.com/en-us/windows/configuration/start/layout)
- [Start policy settings](https://learn.microsoft.com/en-us/windows/configuration/start/policy-settings)

For release validation status, see `VALIDATION.md`. Protect all captures/backups and never upload actual user state to GitHub.
