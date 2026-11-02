# bot-wince-arm

A Windows CE executable for Arm (PE machine 0x1c0, ARMv4).

Windows CE's `.pdata` gives each function's address (not an RVA) and its length in instructions. Imports are called through stubs that load the slot's address from a literal (`ldr ip, [pc, #n]; ldr pc, [ip]`), and calls through registers are `mov lr, pc; mov pc, rN` (ARMv4 has no `blx`). The linker marks `.rsrc` executable; rizin finds three functions in it.

- Source: `pe-arm/bad-60573` from a malware corpus (an `exotic_binaries` collection)
- SHA-256: `c5f7d68af97332f2c957a3531cd1a38760f46f7ab5377838c20613f9282db056`
- Size: 95200 bytes (80830 compressed)
- **Malware:** this file is hostile. It is kept compressed and only ever parsed; never run it.

`bot-wince-arm.rizin.json.zst` holds what rizin 0.8.2 found (`funktion-ab --save`);
`bot-wince-arm.golden` holds what funktion finds (`FUNKTION_BLESS=1 cargo test --test fixtures`).
