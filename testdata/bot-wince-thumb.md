# bot-wince-thumb

A Windows CE executable for Arm with Thumb interworking (PE machine 0x1c2, `THUMB`).

Its `.pdata` marks every function 32-bit, so the code is Arm, though rizin decodes the machine as Thumb and finds one function. Imports are called through interworking stubs (`ldr ip, [pc, #n]; ldr ip, [ip]; bx ip`).

- Source: `pe-thumb/bad-103858` from a malware corpus (an `exotic_binaries` collection); `pe-thumb/bad-112202` is another build of it
- SHA-256: `2ccbfed8f05e6b50bc739c86ce4789030c6bc9e09c88b7c9d41cbcbde52a2455`
- Size: 219648 bytes (79165 compressed)
- **Malware:** this file is hostile. It is kept compressed and only ever parsed; never run it.

`bot-wince-thumb.rizin.json.zst` holds what rizin 0.8.2 found (`funktion-ab --save`);
`bot-wince-thumb.golden` holds what funktion finds (`FUNKTION_BLESS=1 cargo test --test fixtures`).
