# sqlite3-openbsd-amd64

OpenBSD 7.8 on x86-64: the `sqlite3` shell, a PIE whose PLT is split for indirect-branch tracking (`.plt` keeps the lazy-binding entries, `.plt.sec` the stubs calls go to; both start with `endbr64`).

- Source: the OpenBSD 7.8 package `sqlite3-3.50.4` for amd64 (`https://cdn.openbsd.org/pub/OpenBSD/7.8/packages/amd64/sqlite3-3.50.4.tgz`)
- Path in the source: `bin/sqlite3`
- SHA-256: `b68f52f02098f09034f150d5356241ff02f8ca5e2557cfea27f3d04f7153860c`
- Size: 417728 bytes (163805 compressed)
- License: SQLite is public domain

`sqlite3-openbsd-amd64.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`sqlite3-openbsd-amd64.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test --test fixtures`).
