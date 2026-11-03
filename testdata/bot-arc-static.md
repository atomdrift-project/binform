# bot-arc-static

A statically linked, stripped uClibc executable for Synopsys ARCompact (ARC700, little-endian): an IoT botnet client.

Instructions are 16 or 32 bits, stored as halfwords high half first, and a register field of 62 reads a 32-bit `limm` after the instruction: addresses are `mov_s r0, limm`, and callbacks are stored with `st limm, [sp, n]`. Transfers delay only with `.d`. GCC's jump tables are absolute (`cmp_s r0, 13; bhi.d default; ...; ld.as r0, [table, r0]; j_s [r0]`) or bytes after `pcl`, bounded by a compare-and-branch in a delay slot (`brhs.d r1, 7, default; ld r4, [r5, -4]; add_s r1, r1, pcl; ldb_s r1, [r1, 8]; add_s r1, r1, pcl; j_s [r1]`). Built with `-mmillicode`, functions restore their registers by jumping (`b`) into `__ld_r13_to_rN_ret`, a run of `ld rN, [sp, 4 * (N - 13)]` ending in `ld blink, [sp, r12]`; each entry into it is a function of its own. rizin 0.8.2 decodes ARCompact but splits functions at many branch targets, and analyzes `.rodata` too.

- Source: `arc/bad-010a7499d5889e9cd8a9a4c29f67ab42aee290244cda2c2dd2cb54318ba464b6` from a malware corpus (an `exotic_binaries` collection)
- SHA-256: `010a7499d5889e9cd8a9a4c29f67ab42aee290244cda2c2dd2cb54318ba464b6`
- Size: 140740 bytes (74837 compressed)
- **Malware:** this file is hostile. It is kept compressed and only ever parsed; never run it.

`bot-arc-static.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`bot-arc-static.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test --test fixtures`).
