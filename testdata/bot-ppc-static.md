# bot-ppc-static

A statically linked, stripped 32-bit big-endian PowerPC executable (uClibc): an IoT botnet client.

Functions open with `stwu r1, -n(r1)` before `mflr r0` (rizin starts them at the `mflr`). The bot's routines are reached only through addresses the code builds in halves (`lis r9, f@ha; addi r9, r9, f@l`), and one `switch` is a jump table. rizin also starts three functions in the ELF header.

- Source: `ppc/bad-002bfd6bbf31e7ae4b4e0f83cbfb2d040d96117fc9d78fbf90a306e8ab55f765` from a malware corpus (an `exotic_binaries` collection)
- SHA-256: `002bfd6bbf31e7ae4b4e0f83cbfb2d040d96117fc9d78fbf90a306e8ab55f765`
- Size: 51332 bytes (23656 compressed)
- **Malware:** this file is hostile. It is kept compressed and only ever parsed; never run it.

`bot-ppc-static.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`bot-ppc-static.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test fixtures`).
