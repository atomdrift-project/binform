# bot-xtensa-dynamic

A dynamically linked executable for Tensilica Xtensa (little-endian, windowed ABI; GCC) with its symbols kept: an IoT botnet client.

Instructions are two or three bytes, byte-aligned. Constants come from a literal pool of 4-byte words placed *before* the code that reads them: `l32r at, label` loads the word at a negative, word-aligned offset, so a sweep finds the pool words in a pass of their own and steps over them as data. Direct calls are the PC-relative `call0`/`call4`/`call8`/`call12`; `j` jumps, `jx` and `callx` go through a register (often one an `l32r` filled), and every function opens with `entry` and ends with `retw`/`retw.n`, so a sweep seeds each `entry` it finds. Each `.plt` stub is `l32r a8, slot; l32i.n a8, a8, 0; jx a8`. Every one of the 42 functions rizin's symbols name is found, with none past them.

- Source: `xtensa/bad-71c02b99046c3be12e31577aa6623ce47dfb7f369e67af564d2bd499080c03b6` from a malware corpus (an `exotic_binaries` collection)
- SHA-256: `71c02b99046c3be12e31577aa6623ce47dfb7f369e67af564d2bd499080c03b6`
- Size: 34528 bytes (12837 compressed)
- **Malware:** this file is hostile. It is kept compressed and only ever parsed; never run it.

`bot-xtensa-dynamic.rizin.json.zst` holds what rizin 0.8.2 found (`funktion-ab --save`);
`bot-xtensa-dynamic.golden` holds what funktion finds (`FUNKTION_BLESS=1 cargo test --test fixtures`).
