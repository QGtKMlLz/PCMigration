# GitHub publishing text

## Repository name

`PCMigration-Reconciliation`

## Short description

Windows 10/11 migration auditing and selective repair, with an experimental Windows 10 Start-tile recovery module. PowerShell 5.1 and inbox .NET APIs.

## Suggested topics

`windows` `powershell` `migration` `windows-11` `windows-10` `system-administration` `backup` `registry` `winget` `appx` `audit` `disaster-recovery`

## Project summary

PCMigration Reconciliation compares fresh source and destination captures across applications, settings, shortcuts, registry state, Windows/user configuration, integration state, development tools, and secure/manual migration items. It generates transparent CSV/HTML evidence and an inert repair plan. Repairs remain preview-only until individually approved and are independently authorized against the source capture before application. Destination files and narrow registry subtrees are backed up before mutation, followed by fresh verification and optional rollback.

The project intentionally avoids blind profile copies, whole-hive restoration, credential transplantation, protected security databases, and generic copying of unknown application databases.

## v4.1.0 release summary

- Adds the Windows 10 Start workflow omitted from v4.0.0: dual-mode XML capture, encoding-safe diagnosis/build, optional XML policy application, and tiles-only CloudStore restore/rollback.
- Preserves the destination tile-grid identity, validates all registry headers, remaps headers only, accepts matching identities, and backs up the selected policy values.
- New Start captures/backups include integrity manifests. Trusted legacy v2.5.4 Start captures remain accepted with a warning.
- Fixes BOM-less UTF-8 XML decoding so `µ` does not become `Âµ`; keeps the core µ/μ distinction.
- Shortcut copying stays in the individually reviewed core repair plan. Start restore does not blindly copy trees.
- Adds Windows PowerShell 5.1 GitHub validation and logic regressions for scope, mapping, encoding, and capture tampering.
- Retains core schema 4.0; existing v4.0.0 source/destination captures remain usable.
- Updates the full guide, compatibility documentation, omission audit, security notes, and validation boundaries.

## Release designation and limitations

Publish the initial v4.1.0 release as a **prerelease** until the Windows 10 Start module has been exercised on disposable profiles. Package structure/hash checks and static source checks are complete; Windows PowerShell and live Start application were not run in the Linux authoring workspace. The included GitHub validation tests parser/logic behavior, not tile rendering. See `VALIDATION.md`.

The core toolkit supports Windows 10/11. The Start module is Windows 10 only; binary CloudStore recovery is unsupported by Microsoft, with matching builds required by default. Existing v4.0.0 core captures remain compatible; pre-v4 core schemas remain incompatible. Start inputs are separate captures, not core captures or broad registry snapshots. Full firewall import, dedicated taskbar-pin restore, broad Explorer history/ShellBags restoration, and credential transplantation are not new automatic repairs.

Do not claim that SHA256SUMS.txt is digitally signed. Protect real captures/reports/backups and never publish them.

## Files to publish

- All versioned `.ps1` source files.
- `README.md`, `START-MENU.md`, `OMISSION-AUDIT.md`, `VALIDATION.md`, `CAPABILITIES-AND-LIMITATIONS.md`, `CHANGELOG.md`, `SECURITY.md`, `LICENSE`, and `.gitignore`.
- `tests/` and `.github/workflows/validate.yml`.
- `docs/PCMigration-Reconciliation-v4.1.0-Guide.pdf`.
- `SHA256SUMS.txt` and the release ZIP SHA-256 value.

Do not publish source/destination captures, comparison reports, edited repair plans, repair backups, registry snapshots, or real diagnostic output.

## Practical upload sequence

1. Extract the ZIP. Use the **contents** of `PCMigration-Reconciliation-v4.1.0` as the repository root, so README and scripts are at the top level.
2. Include `.gitignore` and `.github/workflows/validate.yml`; browser uploads may hide dot folders, so verify they are present.
3. Commit only source/docs/tests/manifest. Use the release ZIP as a Release asset rather than replacing the source tree with a ZIP file.
4. Allow the Windows validator workflow to finish and resolve failures before promoting the release.
5. Create tag `v4.1.0`, paste the release summary above, and attach the ZIP, standalone PDF, and external release checksum file. Keep the prerelease designation until live Windows 10 validation exists.

The package was prepared for upload; no repository was created or published during authoring.
