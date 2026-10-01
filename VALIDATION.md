# Release validation and test boundaries

## Checks performed while preparing v4.1.0

- Reviewed the actual v4.0.0 suite, v2.5.4 Start capture/diagnosis, and v2.5.6.1 tile fallback.
- Kept the core schema at 4.0; updated script dependency names and tool version metadata.
- Checked script structure with a third-party PowerShell grammar, accounting for grammar limitations in unchanged inherited code. This is not the Microsoft PowerShell parser.
- Checked UTF-8 BOM and CRLF encoding for release PowerShell sources, relative dependencies, safe ZIP paths, exact manifest coverage, archive extraction, and SHA-256 values.
- Created and rendered the updated PDF guide and visually inspected its pages.

## Required Windows checks

The authoring workspace is Linux and has no Microsoft PowerShell runtime. Windows PowerShell 5.1 parser/regression execution, shell rendering, registry imports, policy application, and real source/destination migration were not performed here. Do not describe this release as Windows integration-tested.

On Windows, run `Test-PCMigrationPackage-v4.1.0.ps1` before use. It verifies hashes and parses sources before executing regression code. It includes Start logic checks for authorized registry scope, header-only mapping, same-identity mapping, BOM-less UTF-8 XML, DTD rejection, and changed capture files, alongside the inherited core regression checks. The tests do not change Start, policy, or the registry.

The included GitHub workflow executes the package validator with **Windows PowerShell 5.1** on a Windows runner. It stages the exact tracked repository source without `.git`, then validates with `-StrictPackageContents`. The runner validates parser/logic behavior, not a live Windows 10 tile restore.

Before promoting the experimental Start module to a stable public release, validate capture, preview, apply, sign-out/in rendering, failure recovery, and rollback using disposable Windows 10 user profiles on matching builds. Keep the experimental designation until that evidence exists.

## Editing repository source

Any source or documentation edit changes the packaged checksums. Update `SHA256SUMS.txt` deliberately when preparing the next release; do not rewrite it merely to suppress a validation failure. Run strict validation against the release staging directory. New captures/backups have independent manifests and must never be edited.

Checksums detect changes relative to their manifest. They are not signatures and do not authenticate the maintainer.
