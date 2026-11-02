# libsqlite3-openbsd-arm64.so

OpenBSD 7.8 on A64: every function starts with `bti c` and guards its return address (`retguard`: an `eor` with a cookie, a compare, `brk 1`). Rizin 0.8.2 splits each function after its `bti c` into a one-instruction function and the rest, so it shares few entries with funktion and agrees on few blocks.

- Source: the OpenBSD 7.8 package `sqlite3-3.50.4` for aarch64 (`https://cdn.openbsd.org/pub/OpenBSD/7.8/packages/aarch64/sqlite3-3.50.4.tgz`)
- Path in the source: `lib/libsqlite3.so.37.34`
- SHA-256: `0b9bd19cc66c229d19c9440566d067056fa60443c87710ad5c93525c7387c9ea`
- Size: 2075088 bytes (811407 compressed)
- License: SQLite is public domain

`libsqlite3-openbsd-arm64.so.rizin.json.zst` holds what rizin 0.8.2 found (`funktion-ab --save`);
`libsqlite3-openbsd-arm64.so.golden` holds what funktion finds (`FUNKTION_BLESS=1 cargo test --test fixtures`).
