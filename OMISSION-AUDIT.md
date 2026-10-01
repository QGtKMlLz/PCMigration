# What was omitted from v4.0.0

This audit compares the actual consolidated v4.0.0 distribution with the separate v2.5.4 StartMenu, v2.5.6.1 StartCloudStore, and v2.5.2 WindowsState packages. It distinguishes restored Start capabilities from older standalone operations that remain outside the conservative core repair engine.

| Earlier capability | Status in v4.0.0 | Status in v4.1.0 |
|---|---|---|
| Start-menu shortcut inventory/copy | Included with semantic reconciliation and readable locations | Retained; approved copies use the core repair plan |
| Windows 10 Start XML capture in link and application-ID modes | Separate capture omitted | Included in `Capture-StartMenu` |
| XML encoding fix for µTorrent becoming ÂµTorrent | Core Unicode-path tests existed; the distinct XML decoder fix was omitted with the Start module | Included with encoding-aware XML loading and a BOM-less UTF-8 regression |
| Start tile diagnostics and corrected XML build | Separate script omitted | Included in `Diagnose-Build-StartLayout`; no automatic shortcut-tree copying |
| Explicit XML layout policy application/removal | Separate script omitted | Included with preview/apply gates and selected policy-value backup/rollback |
| Exact tile-grid fallback when XML omitted a source pin | v2.5.6.1 fallback omitted | Included in `Restore-StartTileGrid` with subtree/header validation and independent rollback |
| Full firewall .wfw import | Firewall rules inventoried/reported; the separate full-policy importer was not included | Still manual/outside the core repair engine; no full-policy replacement added |
| Dedicated taskbar-pin XML reconstruction | UserPinned shortcuts inventoried, but no dedicated pin-layout applicator | Still outside the added Start-only module; copying a shortcut does not establish a taskbar pin |
| Broad Explorer Streams/ShellBags/MRU imports from the older WindowsState script | Not carried forward as generic repair; Explorer evidence and selected settings remain | Still outside automatic repair; broad user history is not transplanted |

The complete v4.1.0 package is complete for its documented scope, not a union of every experimental command in every older archive. Unreviewed whole-tree shortcut copies and broader legacy imports were not included merely to make the archive appear comprehensive.

The optimized registry safety backup, core capture/compare/repair/verify/rollback, shortcut equivalence, protected-state exclusions, service restoration, WSL/certificate/WLAN fallbacks, HTML hotfix, and exact Unicode filename handling remain consolidated.

Use `START-MENU.md` for the restored Start workflow and `CAPABILITIES-AND-LIMITATIONS.md` for the current support boundary.
