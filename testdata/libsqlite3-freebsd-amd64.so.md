# libsqlite3-freebsd-amd64.so

FreeBSD 14 on x86-64: SQLite 3.53.4 as the ports tree builds it (Clang, `ELFOSABI_FREEBSD`).

- Source: the FreeBSD package `sqlite3-3.53.4,1` for `FreeBSD:14:amd64` (`https://pkg.freebsd.org/FreeBSD:14:amd64/latest/All/Hashed/sqlite3-3.53.4,1~2$roqhpiei.pkg`, named by that repository's `packagesite.pkg`)
- Path in the source: `/usr/local/lib/libsqlite3.so.3.53.4`
- SHA-256: `8e26a2c79b2267cd8ada15f6fac8a0136228958c1867c926bf95a17dc3926247`
- Size: 1847120 bytes (838859 compressed)
- License: SQLite is public domain

`libsqlite3-freebsd-amd64.so.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`libsqlite3-freebsd-amd64.so.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test --test fixtures`).
