# bot-arcv2-dynamic

A dynamically linked, stripped executable for Synopsys ARCv2 (HS, little-endian): an IoT botnet client.

ARCv2 makes majors 0x08-0x0b 16-bit (`mov_s g, h`, `ld_s r0, [h, u5]`, `jli_s`), gives the 16-bit `h` field five bits with 30 as the `limm` marker, and adds `st w6, [b, s9]` (bit 0 set: a 6-bit immediate, no `limm`), `bi`/`bih` and `leave_s`, which can return. Its PLT has a 32-byte header and a 16-byte stub per import (`ld r12, [pcl, slot]; j.d [r12]; mov r12, pcl`). rizin 0.8.2 cannot decode ARCv2 (it reads the code as x86).

- Source: `arcv2/bad-4545ddd44249a565bdb5a661dd67e25a43d1978d45abf7db6d0b869bee1b0c45` from a malware corpus (an `exotic_binaries` collection)
- SHA-256: `4545ddd44249a565bdb5a661dd67e25a43d1978d45abf7db6d0b869bee1b0c45`
- Size: 30700 bytes (11330 compressed)
- **Malware:** this file is hostile. It is kept compressed and only ever parsed; never run it.

`bot-arcv2-dynamic.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`bot-arcv2-dynamic.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test fixtures`).
