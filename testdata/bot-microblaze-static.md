# bot-microblaze-static

A statically linked, stripped uClibc executable for Xilinx MicroBlaze (big-endian): an IoT botnet client.

Addresses are `imm hi; addik rD, r0, lo` (no literal pools), and the `imm` prefix widens branches too (`imm 1; brlid r15, f`). Only transfers with a `D` bit have delay slots. Built without a barrel shifter, GCC's jump tables scale the case value by adding it to itself: `addik r22, r0, 6; cmpu r18, r4, r22; bltid r18, default; addk r3, r0, r4; addk r3, r4, r4; addk r3, r3, r3; imm hi; addik r3, r3, lo; lwi r3, r3, 0; bra r3`. System calls are `brki r14, 8`, which returns. rizin 0.8.2 has no MicroBlaze analysis to speak of: it finds 13 functions, the entry point the only one funktion shares (the rest lie inside functions, some at odd addresses).

- Source: `microblaze/bad-0cd41af39b4cb9501b2a2e606d8be3c653e930debec2e69ea81f260f70fd6bdc` from a malware corpus (an `exotic_binaries` collection)
- SHA-256: `0cd41af39b4cb9501b2a2e606d8be3c653e930debec2e69ea81f260f70fd6bdc`
- Size: 189076 bytes (76737 compressed)
- **Malware:** this file is hostile. It is kept compressed and only ever parsed; never run it.

`bot-microblaze-static.rizin.json.zst` holds what rizin 0.8.2 found (`funktion-ab --save`);
`bot-microblaze-static.golden` holds what funktion finds (`FUNKTION_BLESS=1 cargo test --test fixtures`).
