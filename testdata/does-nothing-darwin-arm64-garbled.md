# does-nothing-darwin-arm64-garbled

Go on macOS A64 with the function table's magic number overwritten, as the garble obfuscator does; the rest of the header is intact. funktion reads a table its section names, whatever the magic, when the header is a Go 1.18+ one.

- Source: the `does-nothing` program in traits-dev (`testdata/baseline/does-nothing`: `main.go`, which logs one line through k8s.io/klog/v2 v2.130.1), built by Go 1.26.6 with that Makefile's flags: `GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w"`; then the 4-byte magic number of `__gopclntab` (file offset 0xdfd68) overwritten with `a6 ab 7f cc`, the bytes garble wrote in a build of stng's `testdata/garble` program
- SHA-256: `cc8f2e800b26c758bf18118984adb4a323882970ffd1271d34c3abb8c328383f`
- Size: 2132530 bytes (774560 compressed)
- License: Apache-2.0 (traits-dev, klog, logr); the Go runtime is BSD-3-Clause

`does-nothing-darwin-arm64-garbled.rizin.json.zst` holds what rizin 0.8.2 found (`funktion-ab --save`);
`does-nothing-darwin-arm64-garbled.golden` holds what funktion finds (`FUNKTION_BLESS=1 cargo test --test fixtures`).
