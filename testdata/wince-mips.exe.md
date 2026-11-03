# wince-mips.exe

A Windows CE executable for little-endian MIPS IV with FPU (PE machine `0x366`, MIPSFPU).

The code is ordinary little-endian MIPS, decoded as `MipsEl`; PE's MIPS machines (R3000, R4000, R10000, WCE MIPS v2, MIPSFPU) all map there. rizin 0.8.2 finds 61 functions; binform 63, the first ones at the same addresses.

- Source: `pe-mipsfpu/bad-50483` from a malware corpus (an `exotic_binaries` collection)
- SHA-256: `5ac4b7036075988d4a0608ce463836063c864208502135dd784241d11125dd1e`
- Size: 109432 bytes (92944 compressed)
- **Malware:** this file is hostile. It is kept compressed and only ever parsed; never run it.

`wince-mips.exe.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`wince-mips.exe.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test --test fixtures`).
