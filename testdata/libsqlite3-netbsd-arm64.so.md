# libsqlite3-netbsd-arm64.so

NetBSD 10 on A64: SQLite 3.53.4 as pkgsrc builds it (GCC; NetBSD marks its binaries with a note, not the OS/ABI byte).

- Source: the pkgsrc binary package `sqlite3-3.53.4` for NetBSD 10.0 aarch64 (`https://cdn.netbsd.org/pub/pkgsrc/packages/NetBSD/aarch64/10.0/All/sqlite3-3.53.4.tgz`)
- Path in the source: `lib/libsqlite3.so.3.53.4`
- SHA-256: `313cee064fd78dbbea853ae70708ca69da4c081a75d83ed0410b1a5de15a9c8f`
- Size: 1635096 bytes (752688 compressed)
- License: SQLite is public domain

`libsqlite3-netbsd-arm64.so.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`libsqlite3-netbsd-arm64.so.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test fixtures`).
