# does-nothing-linux-arm

Go on 32-bit Arm: A32 only (Go emits no Thumb). Go returns with `add pc, lr, #0` and leaves a zero word (`andeq r0, r0, r0`) after calls that never return and before some functions; both decode, as rizin decodes them. Stripped, so `.gopclntab` names the functions.

- Source: the `does-nothing` program in traits-dev (`testdata/baseline/does-nothing`: `main.go`, which logs one line through k8s.io/klog/v2 v2.130.1), built by Go 1.26.6 with that Makefile's flags: `GOOS=linux GOARCH=arm GOARM=7 go build -trimpath -ldflags="-s -w"`
- SHA-256: `310c9c5b465cfffeaccaed178b6b3f533d36c54d4a6648722c410fcf812b22f3`
- Size: 2162850 bytes (766570 compressed)
- License: Apache-2.0 (traits-dev, klog, logr); the Go runtime is BSD-3-Clause

`does-nothing-linux-arm.rizin.json.zst` holds what rizin 0.8.2 found (`funktion-ab --save`);
`does-nothing-linux-arm.golden` holds what funktion finds (`FUNKTION_BLESS=1 cargo test --test fixtures`).
