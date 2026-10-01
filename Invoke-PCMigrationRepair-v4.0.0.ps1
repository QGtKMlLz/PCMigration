# GitHub publishing text

## Repository name

`PCMigration-Reconciliation`

## Short description

Evidence-first Windows 10/11 migration auditing, selective repair, verification, and rollback using Windows PowerShell 5.1 and inbox .NET APIs.

## Suggested topics

`windows` `powershell` `migration` `windows-11` `windows-10` `system-administration` `backup` `registry` `winget` `appx` `audit` `disaster-recovery`

## Project summary

PCMigration Reconciliation compares fresh source and destination captures across applications, settings, shortcuts, registry state, Windows/user configuration, integration state, development tools, and secure/manual migration items. It generates transparent CSV/HTML evidence and an inert repair plan. Repairs remain preview-only until individually approved and are independently authorized against the source capture before application. Destination files and narrow registry subtrees are backed up before mutation, followed by fresh verification and optional rollback.

The project intentionally avoids blind profile copies, whole-hive restoration, credential transplantation, protected security databases, and generic copying of unknown application databases.

## v4.0.0 release summary

- Complete public package: capture, compare, repair, verify, rollback, shared implementation, registry safety backup, validation, documentation, and PDF guide.
- Functionally equivalent shortcuts no longer appear as repair candidates solely because `.lnk` binary hashes differ.
- Every shortcut report includes a readable relative location, and `Shortcut-Reconciliation.csv` provides a complete source/destination ledger.
- Optional native registry safety snapshots replace slow broad textual backup while remaining forensic-only and impossible to authorize as automatic repair payloads.
- Unicode-safe path behavior preserves `µ` (U+00B5) and keeps it distinct from `μ` (U+03BC), with regression coverage.
- Consolidates PowerShell 5.1 HTML compatibility, protected-state exclusions, shared-read hashing, controlled service quiescing, WLAN/certificate/WSL fallbacks, default-deny repair, source authorization, incremental backups, and exact narrow-registry rollback.

## Suggested release warning

Version 4.0.0 uses capture schema 4.0. Captures created by older releases are incompatible. Create fresh source and destination captures. Treat captures, reports, repair backups, and especially optional `.hiv` snapshots as sensitive; never commit generated migration data to a public repository.

## Files to publish

- All versioned `.ps1` source files.
- `README.md`, `CAPABILITIES-AND-LIMITATIONS.md`, `CHANGELOG.md`, `SECURITY.md`, `LICENSE`, and `.gitignore`.
- `docs/PCMigration-Reconciliation-v4.0.0-Guide.pdf`.
- `SHA256SUMS.txt` and the release ZIP SHA-256 value.

Do not publish source/destination captures, comparison reports, edited repair plans, repair backups, registry snapshots, or real diagnostic output.
