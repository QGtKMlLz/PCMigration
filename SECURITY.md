# Security policy

## Reporting a vulnerability

Do not publish migration captures, repair plans, registry snapshots, credentials, or personally identifying diagnostics in a public issue. Report security defects privately to the repository maintainer and include the smallest sanitized reproduction possible.

## Operator responsibilities

- Run only a package that passes checksum and parser validation.
- Review every approved repair action and keep the default-deny plan behavior.
- Protect captures and backups with access controls and encrypted storage.
- Never commit generated captures, reports, `.hiv` snapshots, or repair backups.
- Never disable endpoint protection merely to capture protected runtime databases.
- Never restore broad registry snapshots wholesale onto another computer.

## Support window

Security fixes are expected for the latest published major release. No automated update mechanism is included.

## Checksums and the Start module

SHA256SUMS.txt is unsigned. It can detect accidental changes relative to the manifest, but is not an authenticity guarantee when both file and manifest can be replaced. Download from a trusted release and compare the release ZIP hash over a trusted channel.

The experimental Start fallback accepts only the selected HKCU tile-grid subtree. Never feed untrusted captures to a registry importer. The legacy v2.5.4 capture format lacks a manifest and is accepted only for compatibility with an explicit warning. Review scope and backup output before `-Apply`.
