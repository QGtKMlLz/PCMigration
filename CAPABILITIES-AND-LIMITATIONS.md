# Capabilities, special fixes, and limitations

## Designed for

- Windows 10 and Windows 11 migration reconciliation.
- One source PC and one destination PC, run in the intended migrated user's interactive session.
- 64-bit Windows PowerShell 5.1 with inbox Windows/.NET components.
- Technicians and advanced users who will inspect evidence and approve individual changes.
- Offline comparison and default-deny destination repair.

## Broad cases covered

- Applications: current/all-user AppX/MSIX evidence, WinGet export/list, 32/64-bit uninstall registrations, Start identities, shortcuts, and portable executable footprints.
- Application settings: recursively inventoried configuration/script files under AppData, LocalAppData, and optionally ProgramData; content-screened source payloads; scoped registry families; browser profile and extension inventories.
- User and shell state: Console Host, regional/language/time zone, 24-hour clock, Explorer/personalization evidence, fonts, default app associations, PowerShell profiles/modules/policies, Windows Terminal, and K-Lite/MPC-HC/Icaros/LAV-related state.
- Integration state: services, scheduled tasks, environment/startup values, printers, mapped drives, VPN/Wi-Fi metadata, optional features, capabilities, firewall rules, SMB shares, ODBC DSNs, certificates, and selected system files.
- Development state: installed tools, Git configuration evidence, WSL distribution inventory with legacy syntax fallback, and VS Code extensions.
- Secure/manual state: certificate/private-key warnings, authentication vaults, browser sessions, licenses, EFS/BitLocker/SSH/GPG/VPN/code-signing keys, and user-selected secure-file candidates.

## Special fixes consolidated in v4.0.0

1. Shortcut semantic reconciliation: `.lnk` files are compared by launch target, arguments, and working directory. Binary-only changes no longer create repair actions.
2. Human-readable shortcut locations: capture and comparison outputs include paths such as `Start Menu (all users)\Programs\Vendor\Tool.lnk`.
3. Complete shortcut ledger: `Shortcut-Reconciliation.csv` shows equivalent, missing, different, and destination-only shortcuts; `Shortcut-Gaps.csv` contains only functional gaps.
4. Unicode-safe paths: U+00B5 `µ` survives capture/copy/reporting and is kept distinct from U+03BC `μ`; a regression test enforces this.
5. PowerShell 5.1 HTML compatibility: report fragments are explicitly joined before `ConvertTo-Html -Body`.
6. Native registry safety snapshots: optional sequential `reg.exe save` snapshots replace slow broad textual backup. They are forensic-only and cannot be authorized as automatic repair payloads.
7. Value-level registry comparison: selective comparison uses deterministic value digests rather than payload-file hashes.
8. Protected registry policy: Wi-Fi/WWAN/EAP authentication, compatibility telemetry, AppModel, credential, and other protected branches are explicit exclusions instead of misleading failures.
9. Volatile/protected file policy: Defender, Kaspersky, Search indexes, notifications/activity stores, diagnostics databases, and thumbnail/icon caches are excluded before enumeration or hashing.
10. Shared-read hashing: ordinary live files are opened with read/write/delete sharing and bounded retries.
11. Controlled service quiescing: verified third-party application services can be stopped around settings capture and are restored in `finally`; critical/security services are denylisted.
12. WLAN inventory recovery: WLAN AutoConfig can be started temporarily and returned to its original state.
13. Certificate fallback: read-only `.NET X509Store` enumeration continues when the PowerShell provider fails.
14. WSL compatibility: modern verbose listing falls back to legacy `wsl.exe --list` output with null-character normalization.
15. Resilient package validation: unlisted files warn by default and fail only with `-StrictPackageContents`; packaged file hashes and parser failures always remain fatal.
16. Source authorization: repair methods, destinations, identities, artifacts, and hashes are reconstructed from the source capture, not trusted solely from the editable plan.
17. Resumable recovery evidence: backup manifests and repair results are persisted during application, and existing narrow registry subtrees are restored exactly after cleanup.

## Explicitly not handled automatically

- Whole-profile or whole-registry restoration.
- Automatic restoration of `HKCU\Software` or `HKLM\SOFTWARE` binary snapshots.
- Passwords, cookies, tokens, credentials, private keys, DPAPI, Windows Hello, passkeys, biometric enrollment, or authenticator secrets.
- Arbitrary application databases or version-bound caches.
- Antivirus/security databases or disabling security products to access them.
- Generic driver installation, service/task recreation, firewall/share changes, certificate private-key import, printer-driver deployment, or license transfer.
- Automatic uninstallation of packages/features/capabilities during rollback.
- Resolving business-policy questions about which destination-specific settings should win.

## Operational limitations

- Old capture schemas are incompatible with v4.0.0; capture both machines again.
- Destination inventory depth must be at least as deep as source inventory depth.
- Incomplete collectors create `Unknown` coverage; they do not prove absence.
- Reparse points are skipped to avoid loops and unintended volumes.
- Machine and application version differences can make technically copyable settings undesirable.
- Store and packaged applications often require reinstall/sign-in/vendor sync rather than file copying.
- Some application installers regenerate shortcuts with equivalent behavior but different icons/descriptions; these are intentionally treated as functionally equivalent.
- The package has no telemetry and no remote orchestration; operators must securely transfer captures and protect report contents.

## Security and privacy

Treat every capture, report, repair plan, backup directory, and especially every `.hiv` snapshot as sensitive. Use BitLocker or equivalently protected storage, restrict ACLs, do not commit captures to Git, and securely retire them after verification. The included `.gitignore` excludes typical generated folders, but it is not a substitute for reviewing staged content.
