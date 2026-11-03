# does-nothing-linux-s390x

Go on IBM Z: 2-, 4- and 6-byte big-endian instructions. Rizin 0.8.2 finds one function here, so the claims are binform's own: the function table's functions recovered and nearly all code covered.

- Source: the `does-nothing` program in traits-dev (`testdata/baseline/does-nothing`: `main.go`, which logs one line through k8s.io/klog/v2 v2.130.1), built by Go 1.26.6 with that Makefile's flags: `GOOS=linux GOARCH=s390x go build -trimpath -ldflags="-s -w"`
- SHA-256: `321af3e34f842c68f633133e5f2e39640258d395ac0caaed8b87bef62b8d2f69`
- Size: 2359458 bytes (798439 compressed)
- License: Apache-2.0 (traits-dev, klog, logr); the Go runtime is BSD-3-Clause

`does-nothing-linux-s390x.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`does-nothing-linux-s390x.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test --test fixtures`).
