# bot-csky-static

A statically linked, stripped, position-independent executable for C-SKY ABIv1 (CK610, little-endian; T-HEAD's GCC, uClibc-ng): an IoT botnet client.

Instructions are 16 bits, with no delay slots. Constants come from literal pools placed after each function's last jump (`lrw rz, [pool]`; `jsri`/`jmpi` call or jump through a pool word). A linear sweep steps over those words, and no function starts in one. PIC code keeps the GOT base in `r14`, computed once per function (`bsr 1f; 1: lrw r14, [offset]; addu r14, r15`), and calls `r14` plus a pool offset (`lrw r7, [offset]; addu r7, r14; jsr r7`). A branch out of `bt`/`br` reach reads the PC the same way and jumps through `r1`. GCC traps with `bsr .` (`0xffff`) and pads with `br .` and `mov r0, r0`. rizin 0.8.2 has no C-SKY support and finds nothing.

- Source: `csky/bad-1577968035891d9ef376e9120e6846470022c3b1a36c79c923ba67cc156dd47e` from a malware corpus (an `exotic_binaries` collection)
- SHA-256: `1577968035891d9ef376e9120e6846470022c3b1a36c79c923ba67cc156dd47e`
- Size: 141808 bytes (78222 compressed)
- **Malware:** this file is hostile. It is kept compressed and only ever parsed; never run it.

`bot-csky-static.rizin.json.zst` holds what rizin 0.8.2 found (`funktion-ab --save`);
`bot-csky-static.golden` holds what funktion finds (`FUNKTION_BLESS=1 cargo test --test fixtures`).
