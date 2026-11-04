# libe_sqlite3-android-x86.so

32-bit x86 position-independent code from clang: `call next; pop ebx; add ebx, GOT` finds the GOT, and jump tables sit at GOT-relative offsets holding GOT-relative entries. Rizin makes a "function" at each `pop ebx`, inside the real one; those show as "inside" in the golden.

- Source: SQLitePCLRaw's `e_sqlite3` native builds as bundled in the `DbaClientX` 1.0.5 NuGet package under `Lib/Core/runtimes/`; SQLite source id 2026-07-24 19:02:57 bf7c7f30
- Path in the source: `Lib/Core/runtimes/android-x86/native/libe_sqlite3.so`
- SHA-256: `43731d621cc2b1fbde62bae8ff465cfe0fd1ea9c2f25d566d3e61e495d226d9f`
- Size: 1820380 bytes (805677 compressed)
- License: Apache-2.0 (SQLitePCLRaw); SQLite itself is public domain

`libe_sqlite3-android-x86.so.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`libe_sqlite3-android-x86.so.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test fixtures`).
