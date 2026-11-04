# bot-nios2-dynamic

A dynamically linked executable for Intel (Altera) Nios II R1, little-endian (glibc), with its symbol table: an IoT botnet client (`udpattack`, `tcpattack`, `cmdparse`).

Instructions are 32 bits, without delay slots. Calls into the PLT are `call` (a 26-bit word index); each PLT entry loads its GOT slot through a constant (`movhi r15, %hiadj(slot); ldw r15, %lo(slot)(r15); jmp r15`), which the decoder follows to the import. rizin 0.8.2 has no Nios II support: it decodes the file as x86 and lists each symbol as a 2-byte function.

- Source: `nios2/bad-7f71577b63b449c1a9e9aa516fa9e4320fe5f79548a00025a430894a269ab57b` from a malware corpus (an `exotic_binaries` collection)
- SHA-256: `7f71577b63b449c1a9e9aa516fa9e4320fe5f79548a00025a430894a269ab57b`
- Size: 24468 bytes (6866 compressed)
- **Malware:** this file is hostile. It is kept compressed and only ever parsed; never run it.

`bot-nios2-dynamic.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`bot-nios2-dynamic.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test fixtures`).
