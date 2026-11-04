# ebpf-lirc-grundig

An eBPF relocatable object (clang, little-endian): a `lirc_mode2` infrared decoder for Grundig remotes, one program (`bpf_decoder`) in the section `lirc_mode2/grundig`, with a map and a license section.

Instructions are 8 bytes, `lddw` 16; jumps count instructions from the next one. The program is one function, named by its `.symtab` symbol; helper calls (`call` with source register 0) are calls to the kernel, not to code in the file. rizin 0.8.2 finds a single 16-byte block of the 1008-byte program.

- Source: `bpf/good-grundig.o` from the `exotic_binaries` collection
- SHA-256: `2daf05c01972033a32035f4f4606e734350ab095fe1f1d1c1cfb5a54374a5d91`
- Size: 2288 bytes (767 compressed)

`ebpf-lirc-grundig.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`ebpf-lirc-grundig.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test fixtures`).
