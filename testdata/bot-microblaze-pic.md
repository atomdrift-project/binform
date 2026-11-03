# bot-microblaze-pic

A statically linked, stripped uClibc executable for Xilinx MicroBlaze (big-endian), built position-independent: an IoT botnet client.

Functions find the GOT from the PC (`mfs r20, rpc; imm 1; addik r20, r20, n`) and call through it (`imm 0xffff; lwi r3, r20, -0x174; brald r15, r3`); linked statically, each slot holds its target's address. `_start` passes `main`, `_init` and `_fini` to `__uClibc_main` as `imm`-built addresses in `r5`, `r8` and `r9`. rizin 0.8.2 has no MicroBlaze analysis to speak of: it finds 4 functions, the entry point the only one binform shares (the rest lie inside functions, some at odd addresses).

- Source: `microblaze/bad-16887494476cea5217111a37d0f8f6264c519c4573a9f009d877245db771e77f` from a malware corpus (an `exotic_binaries` collection)
- SHA-256: `16887494476cea5217111a37d0f8f6264c519c4573a9f009d877245db771e77f`
- Size: 143216 bytes (50528 compressed)
- **Malware:** this file is hostile. It is kept compressed and only ever parsed; never run it.

`bot-microblaze-pic.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`bot-microblaze-pic.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test --test fixtures`).
