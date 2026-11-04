# does-nothing-linux-mips

Go on big-endian 32-bit MIPS: the function table is read in the file's byte order, and each branch, jump and call decodes with its delay slot as one instruction. Rizin gives a delay slot reached by falling through a branch a block of its own, so it counts more blocks; it also starts a function in the epilogue after each `jal runtime.deferreturn`, code the Go runtime resumes at and no instruction reaches.

- Source: the `does-nothing` program in traits-dev (`testdata/baseline/does-nothing`: `main.go`, which logs one line through k8s.io/klog/v2 v2.130.1), built by Go 1.26.6 with that Makefile's flags: `GOOS=linux GOARCH=mips go build -trimpath -ldflags="-s -w"`
- SHA-256: `8ced816b572ce55efd40f7e9279b4db785d4b51ed1f82f37687883039d76e3a6`
- Size: 2425025 bytes (726167 compressed)
- License: Apache-2.0 (traits-dev, klog, logr); the Go runtime is BSD-3-Clause

`does-nothing-linux-mips.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`does-nothing-linux-mips.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test fixtures`).
