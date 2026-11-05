# Contributing

binform reads hostile input, so correctness comes first and simplicity
second. A change that improves recovery on one binary and worsens it on
another needs corpus evidence for which matters more.

## Building

```sh
make test     # cargo test --workspace --all-features
make lint     # rustfmt --check, clippy and rustdoc, warnings denied
make fmt      # cargo fmt --all
make install  # install the binform and binform-ab tools
```

CI runs these with warnings denied on Linux, Windows and macOS, builds the
library on the minimum supported Rust (`rust-version` in `Cargo.toml`), and
runs the fuzz targets in `fuzz/` for a few minutes each.

## Fixtures

`testdata/` holds real binaries, zstd-compressed; many are malware. Never
run them: the tests only parse them. Most have a `.golden` file of what
binform recovers and a frozen rizin listing it is checked against; see
[testdata/README.md](testdata/README.md).

A change in recovery shows up as a golden diff. When the diff is the point
of the change, accept it and say why in the commit:

```sh
BINFORM_BLESS=1 cargo test fixtures
git diff --stat testdata/
```

A refactor leaves every golden byte-identical.

## Rules

- No `unsafe`, no I/O, no subprocesses, no global state.
- Library code does not panic on any input: no indexing, `unwrap`,
  `expect` or overflowing arithmetic. Clippy enforces this outside tests.
- Every loop over something the input controls is bounded: by the bytes it
  reads, by a budget in `src/layout/limits.rs`, or by `Limits`. A malformed
  entry ends its table, not the file.
- A heuristic gets a comment naming the pattern it is for, and a test in
  `src/tests/synthetic.rs` holding the few instructions of that pattern.
- Comments say what the code does and why, not how it came to be.

[docs/design.md](docs/design.md) has the rest.

## Syscall names

`src/syscalls.rs` is generated from the `libc` crate's tables. Do not edit
it by hand:

```sh
python -I tools/syscalls.py path/to/libc-0.2.x > src/syscalls.rs
```

Security issues: see [SECURITY.md](SECURITY.md).
