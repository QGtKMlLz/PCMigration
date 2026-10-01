# Changelog

## 4.1.0 - 2026-09-30

- Restored the omitted Windows 10 Start capture, dual XML diagnostics/build/policy workflow, and tile-grid-only restore/rollback.
- Added encoding-aware XML loading for BOM-less UTF-8 and the µ/Âµ case.
- Replaced wholesale shortcut copying with the existing individually reviewed core shortcut repair.
- Added registry-header confinement, header-only remapping, same-identity support, capture integrity checks, and selected policy-value backups.
- Added session-scoped shell stopping, failure rollback, and Explorer/temp-file cleanup.
- Retained core schema 4.0 and compatibility with v4.0.0 captures. Start schema is separately versioned; trusted v2.5.4 Start captures remain accepted.
- Added Windows PowerShell 5.1 GitHub validation and Start logic regression tests.
- Package validator stops before executing regression code if integrity/parser checks fail.
- Updated documentation and PDF; explicitly documented remaining firewall/taskbar/credential limitations.

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
