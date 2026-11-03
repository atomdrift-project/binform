# libsqlite3-solaris-sparc.so

Solaris 10 on 32-bit SPARC (V8+): SQLite 3.32.3 built by OpenCSW with Sun Studio. Constant pools (`___const_seg_*` objects) sit in `.text`, calls are linked by text relocations, and leaf functions tail-call with `mov %o7, %g1; call f; mov %g1, %o7`.

- Source: the OpenCSW package `libsqlite3_0-3320300,REV=2020.08.10` for SunOS 5.10 sparc (`https://mirror.opencsw.org/opencsw/testing/sparc/5.10/libsqlite3_0-3320300%2cREV%3d2020.08.10-SunOS5.10-sparc-CSW.pkg.gz`, an SVR4 package datastream)
- Path in the source: `root/opt/csw/lib/libsqlite3.so.0.8.6`
- SHA-256: `1c6d3193b4b6cd24e01288b8b1ed5fe31e22a0425d8a2f5e413ad78b2f2aa2f0`
- Size: 1274780 bytes (598807 compressed)
- License: SQLite is public domain

`libsqlite3-solaris-sparc.so.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`libsqlite3-solaris-sparc.so.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test --test fixtures`).
