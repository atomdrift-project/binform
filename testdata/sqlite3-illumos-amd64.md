# sqlite3-illumos-amd64

illumos (SmartOS) on x86-64: the `sqlite3` shell, `ELFOSABI_SOLARIS`, linked by the illumos link editor.

- Source: the SmartOS pkgsrc 2024Q4 package `sqlite3-3.47.2` (`https://pkgsrc.smartos.org/packages/SmartOS/2024Q4/x86_64/All/sqlite3-3.47.2.tgz`, a signed `ar` archive around the tarball)
- Path in the source: `bin/sqlite3`
- SHA-256: `cfdc2095b9ce7f8e26d125e419734cee3290beefd3012f967952bde858f55439`
- Size: 413920 bytes (164131 compressed)
- License: SQLite is public domain

`sqlite3-illumos-amd64.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`sqlite3-illumos-amd64.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test --test fixtures`).
