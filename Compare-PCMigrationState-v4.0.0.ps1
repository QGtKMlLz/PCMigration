# Changelog

## 4.0.0 - 2026-09-18

- Consolidated the complete v3.2.1 toolkit and v3.3 registry-backup revision.
- Added semantic shortcut comparison and comprehensive relative-location reporting.
- Suppressed functionally equivalent shortcut binaries from repair plans.
- Added `Shortcut-Reconciliation.csv` and `Shortcut-Equivalent-Binary-Differences.csv`.
- Added explicit Unicode Form C comparison while preserving `µ` and `μ` as distinct characters.
- Added optional native forensic registry snapshots behind `-CaptureRegistrySafetyBackup`.
- Added `-RegistryBackupTargetedOnly` for narrow safety exports without broad hives.
- Made unlisted package files warnings by default and strict failures with `-StrictPackageContents`.
- Retained the PowerShell 5.1 HTML-body hotfix, protected-state exclusions, shared-read hashing, service restoration auditing, certificate fallback, WLAN recovery, WSL legacy fallback, source-authorized repair, incremental backups, and exact narrow-registry rollback.
- Advanced capture schema to 4.0; earlier captures must not be reused.
