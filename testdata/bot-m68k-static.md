# bot-m68k-static

A statically linked, stripped uClibc executable for the Motorola 68020 (big-endian): an IoT botnet client.

It uses the 68020's additions throughout: `bsr.l` and `jsr` with 32-bit displacements, `extb.l`, 32-bit `mulu.l`/`divu.l`, bit fields, and scaled indexes. rizin 0.8.2 decodes none of them (it reads `bsr.l`, `0x61ff`, as invalid, and stops each function there), so it finds 41 functions, 16 of them at odd addresses in `.rodata`. Start-up code passes `main` by pushing it (`pea.l main.l; jsr __libc_start_main`), and the bot registers its attack routines the same way, so their addresses are the only way to them. GCC's jump tables are halfword offsets from the table after the jump (`move.w (2, pc, d0.l*2), d0; jmp (2, pc, d0.w)`), bounded in memory and reloaded (`moveq #10, d1; cmp.l 12(a3), d1; bcs default; move.l 12(a3), d0`).

- Source: `m68k/bad-00d228fea87c5d1200e530ce4d669ca6d571cece35bf6e09b66e28284af4edb0` from a malware corpus (an `exotic_binaries` collection)
- SHA-256: `00d228fea87c5d1200e530ce4d669ca6d571cece35bf6e09b66e28284af4edb0`
- Size: 46516 bytes (19282 compressed)
- **Malware:** this file is hostile. It is kept compressed and only ever parsed; never run it.

`bot-m68k-static.rizin.json.zst` holds what rizin 0.8.2 found (`funktion-ab --save`);
`bot-m68k-static.golden` holds what funktion finds (`FUNKTION_BLESS=1 cargo test --test fixtures`).
