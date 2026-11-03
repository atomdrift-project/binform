# race_linux_arm64.syso

The Go race detector's runtime (LLVM TSan, C++) as an A64 ELF object: 751 functions, each reached through relocated `bl`s. Without relocation every call reads as `bl` to itself.

- Source: the Go 1.26.6 distribution (`go1.26.6.windows-386.zip` from go.dev/dl)
- Path in the source: `go/src/runtime/race/race_linux_arm64.syso`
- SHA-256: `d41557a3276a80727aadad0bdd3063428415ca2b4c3302c07820389fbf1f31dc`
- Size: 567296 bytes (140757 compressed)
- License: BSD-3-Clause (the Go license)

`race_linux_arm64.syso.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`race_linux_arm64.syso.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test --test fixtures`).
