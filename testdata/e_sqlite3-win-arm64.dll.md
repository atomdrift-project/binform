# e_sqlite3-win-arm64.dll

MSVC A64: `.pdata` holds entries for function fragments (unwind codes beginning with `end_c`) and for the parts of shrink-wrapped functions. Neither starts a function.

- Source: SQLitePCLRaw's `e_sqlite3` native builds as bundled in the `DbaClientX` 1.0.5 NuGet package under `Lib/Core/runtimes/`; SQLite source id 2026-07-24 19:02:57 bf7c7f30
- Path in the source: `Lib/Core/runtimes/win-arm64/native/e_sqlite3.dll`
- SHA-256: `e986c56839d93cabfdbaefd20a6bae2b23185bde34110503c2e7b2c1790af20a`
- Size: 1827808 bytes (784943 compressed)
- License: Apache-2.0 (SQLitePCLRaw); SQLite itself is public domain

`e_sqlite3-win-arm64.dll.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`e_sqlite3-win-arm64.dll.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test --test fixtures`).
