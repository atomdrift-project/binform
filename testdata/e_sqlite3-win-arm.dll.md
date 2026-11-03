# e_sqlite3-win-arm.dll

MSVC for Windows on 32-bit Arm (PE machine `ARMNT`, Thumb-2 only). `.pdata` entries carry Thumb's bit 0; packed entries and `.xdata` with the `F` bit set are fragments, which start no function. Imports are called through a slot address loaded from a literal pool (`ldr r4, [pc, #n]; ldr r3, [r4]; blx r3`) or through 12-byte thunks (`movw ip; movt ip; ldr.w pc, [ip]`). Rizin 0.8.2 does not read ARMNT's `.pdata`, so binform finds some 600 functions it does not.

- Source: the NuGet package SQLitePCLRaw.lib.e_sqlite3 2.1.10 (`https://www.nuget.org/api/v2/package/SQLitePCLRaw.lib.e_sqlite3/2.1.10`)
- Path in the source: `runtimes/win-arm/native/e_sqlite3.dll`
- SHA-256: `b49944bc69bc5bf7f013bf7c52ed554b66c8a7029dbe07ba7ec377af30bbb079`
- Size: 1256960 bytes (688338 compressed)
- License: Apache-2.0 (SQLitePCLRaw); SQLite itself is public domain

`e_sqlite3-win-arm.dll.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`e_sqlite3-win-arm.dll.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test --test fixtures`).
