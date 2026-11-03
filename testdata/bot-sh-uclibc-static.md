# bot-sh-uclibc-static

A statically linked, stripped uClibc executable for little-endian SuperH (SH-4): an IoT botnet client.

Calls load the callee from a literal pool after the function (`mov.l @(disp, pc), r1; jsr @r1`); `.init` and `.fini` call with `mova 1f, r0; braf r1; lds r0, pr`, returning past a literal; the bot's own routines are reached mostly through code addresses in literal pools. rizin also starts a function at 0x40b288, inside the `/dev/watchdog` string in `.rodata`.

- Source: `sh/bad-00cf03ec5a9d69e8725e41eaf0181628b73b3afdc0122931dd63a89c41acf77f` from a malware corpus (an `exotic_binaries` collection)
- SHA-256: `00cf03ec5a9d69e8725e41eaf0181628b73b3afdc0122931dd63a89c41acf77f`
- Size: 48260 bytes (28187 compressed)
- **Malware:** this file is hostile. It is kept compressed and only ever parsed; never run it.

`bot-sh-uclibc-static.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`bot-sh-uclibc-static.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test --test fixtures`).
