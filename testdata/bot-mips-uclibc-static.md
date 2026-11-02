# bot-mips-uclibc-static

A statically linked, stripped uClibc executable for big-endian MIPS-I: an IoT botnet client.

No symbols, no dynamic section: `$gp` comes from the `.got` section (0x7ff0 past its start, as `__start` computes it with `bal; lui; addiu; addu $gp, $gp, $ra`), calls go through the GOT (`lw $t9, n($gp); jalr $t9`), and the bot's own routines are reached only through function pointers the GOT holds.

- Source: `mips/6a995d185a72559ba2e22e4edb0e198a7fa6332aa8cbb7066047d43e02dcd0e7.elf` from a malware corpus (an `exotic_binaries` collection)
- SHA-256: `6a995d185a72559ba2e22e4edb0e198a7fa6332aa8cbb7066047d43e02dcd0e7`
- Size: 57076 bytes (19088 compressed)
- **Malware:** this file is hostile. It is kept compressed and only ever parsed; never run it.

`bot-mips-uclibc-static.rizin.json.zst` holds what rizin 0.8.2 found (`funktion-ab --save`);
`bot-mips-uclibc-static.golden` holds what funktion finds (`FUNKTION_BLESS=1 cargo test --test fixtures`).
