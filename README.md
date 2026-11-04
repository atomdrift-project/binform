# binform

binform recovers functions from machine code: where each one starts and
ends, its basic blocks, its cyclomatic complexity, and the calls and jumps it
makes. It is a pure-Rust library with no `unsafe`, no subprocesses, and no
I/O: recovery is a function of its input, never panics, and bounds its work by
configurable `Limits`, because the input is assumed hostile.

It covers x86/x86-64, Arm/Thumb, AArch64, MIPS, PowerPC (including Windows
NT's little-endian PowerPC), RISC-V, LoongArch, s390x, SPARC, SuperH, m68k,
OpenRISC, MicroBlaze, ARC, C-SKY, M*Core, Nios II, Xtensa and eBPF, in
ELF, PE and Mach-O binaries.

The API is three functions over plain data, and a caller pays only for
what it calls:

- `parse` reads the headers into a `Binary`: format, instruction set,
  entry point, sections, imports and exports.
- `recover` recovers its functions.
- `calls` yields every call and syscall site, one per address, with the
  values its arguments carry: constants, and the bytes behind a pointer
  (a `sockaddr` built on the stack).

`Binary::syscall` names a Linux syscall number for the binary's
architecture, and `Binary::syscall_number` is its inverse: the number a libc
wrapper such as `connect` issues. A binary of an instruction set binform
does not decode still parses: it has a layout, no `arch`, and no functions.

```rust
let bytes = std::fs::read("a.out")?;
let bin = binform::parse(&bytes)?;
let recovery = binform::recover(&bin, &binform::Limits::DEFAULT);
for f in &recovery.functions {
    println!("{:#x} {} blocks, complexity {}", f.entry, f.blocks, f.complexity);
}
for call in binform::calls(&bin, &recovery) {
    if let binform::Target::Syscall(Some(n)) = call.target {
        println!("{:#x} syscall {:?} {:?}", call.addr, bin.syscall(n), call.args);
    }
}
```

## Scope

binform reports what code mechanically does; its callers decide what it
means. It does the per-instruction-set work that gives the same answer
whoever asks: instruction boundaries, functions, blocks, complexity, calls
and jumps, and the constants that reach an instruction. Anything that needs
domain meaning or emulation stays with the caller: what a syscall implies,
whether bytes are a string or a key, following a decoder loop.

[docs/design.md](docs/design.md) gives the rules the code keeps, and
[docs/limitations.md](docs/limitations.md) what it does not yet read, per
instruction set.

## Accuracy

Every fixture in `testdata/` is a real binary. Its `.golden` file records
what binform recovers, function by function, beside an independent
reference listing (from rizin), so any change in recovery shows up as a
diff, and each fixture asserts the specific gap it was added for. See
[testdata/README.md](testdata/README.md). `tools/` has `binform`, which
prints what binform recovers as JSON, and `binform-ab`, which compares it
with rizin over a corpus.

binform is part of the [atomdrift project](https://github.com/atomdrift-project).
Contributions are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md).

Licensed under Apache-2.0.
