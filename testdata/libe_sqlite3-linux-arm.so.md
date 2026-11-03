# libe_sqlite3-linux-arm.so

32-bit Arm C from GCC, nearly all Thumb-2: Thumb symbols, entries and branch targets carry bit 0, and `blx` switches mode. The PLT is A32 (a 20-byte header, then 12-byte `add ip, pc; add ip, ip; ldr pc, [ip, #n]!` stubs), whose slots the decoder follows. Rizin gives entries as even addresses; the fixture test clears bit 0 before it compares. `tbb`/`tbh` jump tables are not read yet, so their cases are not explored.

- Source: SQLitePCLRaw's `e_sqlite3` native builds, NuGet package `SQLitePCLRaw.lib.e_sqlite3` 2.1.10
- Path in the source: `runtimes/linux-arm/native/libe_sqlite3.so`
- SHA-256: `d39354a7f5a345a7d22d9da13303cfb9168745f7f4ba428a23ca11555a76efa3`
- Size: 879532 bytes (511196 compressed)
- License: Apache-2.0 (SQLitePCLRaw); SQLite itself is public domain

`libe_sqlite3-linux-arm.so.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`libe_sqlite3-linux-arm.so.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test --test fixtures`).
