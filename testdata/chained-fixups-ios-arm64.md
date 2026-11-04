# chained-fixups-ios-arm64

An iOS A64 executable (UIKit, Security, libsqlite3, libz) linked with chained fixups: `LC_DYLD_CHAINED_FIXUPS` and no `LC_DYLD_INFO`, its 93 imports in a `DYLD_CHAINED_IMPORT` table. It is a layout fixture: `layout::tests::chained_fixup_imports_agree_with_the_symbol_table` checks that the chained import table binds every import to the library its symbol's two-level ordinal names, so the table reader is tested on a real file. It has no golden or rizin file; its functions are not compared.

goblin reads no chained fixups, so filefacts' goblin path listed these imports from `LC_SYMTAB` with no library; binform names every one (`binform-ab goblin` found it).

- Source: `mislabeled-good/macho/c2393fceab76__good/mislabeled-bad/c2393fceab76776e19848c2ca3c84bea0ed224ac53206c48f1c5fd525ef66306.macho` from the `triage` corpus
- SHA-256: `c2393fceab76776e19848c2ca3c84bea0ed224ac53206c48f1c5fd525ef66306`
- Size: 87224 bytes (12024 compressed)
- **Possibly malware:** the corpus labels it both ways. It is kept compressed and only ever parsed; never run it.
