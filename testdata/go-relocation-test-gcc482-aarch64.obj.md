# go-relocation-test-gcc482-aarch64.obj

An A64 ELF relocatable object from GCC 4.8.2. Its sections all claim address zero and its one function sits at offset zero, which a reader of executables skips. binform places the sections as rizin does (0x8000000 plus the file offset) and keeps symbols at offset zero.

- Source: the Go 1.26.6 distribution (`go1.26.6.windows-386.zip` from go.dev/dl)
- Path in the source: `go/src/debug/elf/testdata/go-relocation-test-gcc482-aarch64.obj`
- SHA-256: `b77a9d858ab8132a3742bc6e9bd84cb644b59567aacaf78b127726485adc9d7a`
- Size: 3392 bytes (941 compressed)
- License: BSD-3-Clause (the Go license)

`go-relocation-test-gcc482-aarch64.obj.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`go-relocation-test-gcc482-aarch64.obj.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test fixtures`).
