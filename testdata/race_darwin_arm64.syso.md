# race_darwin_arm64.syso

The same runtime as an A64 Mach-O `MH_OBJECT`. Unlinked, its `bl 0` placeholders would make thousands of one-instruction "functions"; binform applies the branch relocations.

- Source: the Go 1.26.6 distribution (`go1.26.6.windows-386.zip` from go.dev/dl)
- Path in the source: `go/src/runtime/race/race_darwin_arm64.syso`
- SHA-256: `6ca6a32e8b650ac03b6a11b40c7a0cdd938d00046bd1c942f7c530e0fdaf23b2`
- Size: 502032 bytes (141280 compressed)
- License: BSD-3-Clause (the Go license)

`race_darwin_arm64.syso.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`race_darwin_arm64.syso.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test fixtures`).
