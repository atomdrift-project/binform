# cycle.elf

An x86-64 ELF relocatable object: the same layout question, on x86-64.

- Source: the Go 1.26.6 distribution (`go1.26.6.windows-386.zip` from go.dev/dl)
- Path in the source: `go/src/debug/dwarf/testdata/cycle.elf`
- SHA-256: `835eeac175aa25a4ab12bc9f2c441094e2eefe76be1f963773662f1bfcf559c6`
- Size: 2624 bytes (759 compressed)
- License: BSD-3-Clause (the Go license)

`cycle.elf.rizin.json.zst` holds what rizin 0.8.2 found (`funktion-ab --save`);
`cycle.elf.golden` holds what funktion finds (`FUNKTION_BLESS=1 cargo test --test fixtures`).
