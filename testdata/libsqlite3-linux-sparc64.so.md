# libsqlite3-linux-sparc64.so

Debian on SPARC V9: SQLite 3.53.4 built by GCC. Its `.plt` is writable and, in the file, holds only each entry's first instructions: the header they branch to is zeros until the dynamic linker fills it.

- Source: the Debian ports package `libsqlite3-0_3.53.4-2_sparc64.deb` (`https://deb.debian.org/debian-ports/pool-sparc64/main/s/sqlite3/libsqlite3-0_3.53.4-2_sparc64.deb`)
- Path in the source: `./usr/lib/sparc64-linux-gnu/libsqlite3.so.3.53.4`
- SHA-256: `6a62cf8f77b903a3d3d3999901bfea4bfea08ea42f28be1dc712c58fe94e9ca3`
- Size: 2158424 bytes (651897 compressed)
- License: SQLite is public domain

`libsqlite3-linux-sparc64.so.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`libsqlite3-linux-sparc64.so.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test --test fixtures`).
