# does-nothing-windows-arm64.exe

Go on Windows A64: no `.pdata`, so nothing but the entry point and calls names a function. Go's function table (`runtime.pclntab`) has no section of its own in a PE file; binform finds its header in `.rdata`. The header leaves the text start to the loader (0), so entries count from `.text`.

- Source: the `does-nothing` program in traits-dev (`testdata/baseline/does-nothing`: `main.go`, which logs one line through k8s.io/klog/v2 v2.130.1), built by Go 1.26.6 with that Makefile's flags: `GOOS=windows GOARCH=arm64 go build -trimpath -ldflags="-s -w"`
- SHA-256: `25c649cf2f6829fb4cc18cb8dad48ff23b2a7c98ba0c569a80a7446f91683d47`
- Size: 2153984 bytes (771241 compressed)
- License: Apache-2.0 (traits-dev, klog, logr); the Go runtime is BSD-3-Clause

`does-nothing-windows-arm64.exe.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`does-nothing-windows-arm64.exe.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test --test fixtures`).
