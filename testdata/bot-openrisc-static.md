# bot-openrisc-static

A statically linked, stripped uClibc executable for OpenRISC 1000 (`or1k`, big-endian): an IoT botnet client.

Every jump, branch and call has a delay slot. Start-up code reads its own address with `l.jal` to just past the slot (`l.jal 1f; l.movhi r2, 0; 1:`) and reads a word of data it jumps over (`l.jal 1f; l.ori r3, r1, 0; .word x; 1: l.lwz r4, 0(r9)`): neither is a call. Addresses and integers alike are built with `l.movhi; l.ori`, so some constants (`100000` is `0x186a0`) fall inside code without being a function's address. Five tail calls go through function pointers loaded from memory (`l.lwz r17, 12(r3); l.jr r17; l.addi r1, r1, 20`). rizin 0.8.2 has no OpenRISC support: of the 53 functions it reports, all but the entry point lie at odd addresses.

- Source: `openrisc/bad-31b49b7f11276d9f390bd221cac81ff7bb3c0804df440afbc811416ae14deb7e` from a malware corpus (an `exotic_binaries` collection)
- SHA-256: `31b49b7f11276d9f390bd221cac81ff7bb3c0804df440afbc811416ae14deb7e`
- Size: 164564 bytes (80285 compressed)
- **Malware:** this file is hostile. It is kept compressed and only ever parsed; never run it.

`bot-openrisc-static.rizin.json.zst` holds what rizin 0.8.2 found (`funktion-ab --save`);
`bot-openrisc-static.golden` holds what funktion finds (`FUNKTION_BLESS=1 cargo test --test fixtures`).
