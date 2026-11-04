# Contributing to binform

Thank you for helping. binform reads hostile input, so the bar is
correctness first, then simplicity; a change that makes recovery better on
one binary and worse on another needs the corpus evidence to say which
matters more.

## Building and testing

```sh
cargo test --workspace          # unit tests, hand-assembled idioms, fixtures
cargo clippy --workspace --all-targets
cargo fmt --all
```

CI runs the same commands with warnings denied, builds the library on the
minimum supported Rust (`rust-version` in `Cargo.toml`), and runs the fuzz
targets in `fuzz/` for a few minutes (`cargo +nightly fuzz run parse`).

## Fixtures and goldens

`testdata/` holds real binaries, most of them malware, zstd-compressed.
Never run them: tests only parse them. Each has a `.golden` file of what
binform recovers and a frozen reference listing it is checked against; see
[`testdata/README.md`](testdata/README.md).

A change in recovery shows up as a golden diff. When the diff is the point
of the change, accept it and say why in the commit:

```sh
BINFORM_BLESS=1 cargo test fixtures
git diff --stat testdata/
```

A refactor must leave every golden byte-identical.

## Rules the code keeps

- No `unsafe`, no I/O, no subprocesses, no global state.
- Library code never panics on any input: no indexing, `unwrap`, `expect`
  or overflowing arithmetic (clippy enforces this outside tests). Read
  through the checked readers in `layout::read` and `isa`.
- Every loop over something the input controls is bounded: by the bytes
  it reads, by a named limit in `layout::limits`, or by `Limits`. A
  malformed entry ends its table, never the file.
- A behaviour that only a heuristic justifies gets a comment naming the
  binary pattern it is for, and a test in `src/tests/synthetic.rs` that
  holds the few instructions of that pattern.
- Comments say what the code does and why, not how it came to be.

## Syscall names

`src/syscalls.rs` is generated from the `libc` crate's tables; do not edit
it by hand:

```sh
python -I tools/syscalls.py path/to/libc-0.2.x > src/syscalls.rs
```

## Reporting a security issue

See [SECURITY.md](SECURITY.md).
