# bot-mcore-static

A statically linked, stripped executable for Motorola M*Core (RCE), little-endian (uClibc): an IoT botnet client.

M*Core is the set C-SKY ABIv1 descends from, and binform decodes it with the C-SKY decoder: 16-bit instructions, no delay slots, literal pools after each function (`lrw rz, [pool]`; `jsri`/`jmpi` call or jump through a pool word), `rts` as `jmp r15`, `mov r0, r0` padding. `_start` loads `main` from its pool and calls `__uClibc_main` through `jsri`. rizin 0.8.2 decodes this file in the wrong byte order (odd branch targets, `r20`, unaligned pool addresses) and its 2534 "functions" are noise; it is kept for the record, not as a target.

- Source: `mcore/bad-c5138544e88df7b6cb2abaf967e606aead6221ad415cd1e93be58da4fbdad819` from a malware corpus (an `exotic_binaries` collection)
- SHA-256: `c5138544e88df7b6cb2abaf967e606aead6221ad415cd1e93be58da4fbdad819`
- Size: 208964 bytes (79587 compressed)
- **Malware:** this file is hostile. It is kept compressed and only ever parsed; never run it.

`bot-mcore-static.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`bot-mcore-static.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test fixtures`).
