# binform

binform finds the functions in a binary. Given the bytes of an ELF, PE or
Mach-O file, it reports where each function starts and ends, its basic
blocks and complexity, the calls and jumps it makes, and the arguments its
calls and syscalls pass. It is a Rust library with no `unsafe`, no I/O and
no panics, and its work is bounded by `Limits`. The input is assumed hostile.

```rust
let bytes = std::fs::read("a.out")?;
let bin = binform::parse(&bytes)?;
let recovery = binform::recover(&bin, &binform::Limits::DEFAULT);
for f in &recovery.functions {
    println!("{:#x} {} blocks", f.entry, f.blocks);
}
```

It decodes x86, Arm, AArch64, MIPS, PowerPC, RISC-V, LoongArch, s390x,
SPARC, SuperH, m68k, OpenRISC, MicroBlaze, ARC, C-SKY, M\*Core, Nios II,
Xtensa and eBPF.

## Why not goblin or rizin

goblin parses headers: sections, symbols, imports. It does not read code.
binform parses the headers itself and goes on to the code.

rizin does far more: debugging, emulation, decompilation, scripting. It is
also a large LGPL C framework, reached from Rust through a subprocess or
bindings. binform is one Rust dependency. It does less on purpose: it says
what the code does and leaves what that means to the caller.

rizin is the yardstick. `tools/binform-ab` has compared the two on thousands
of binaries, many of them malware, and the test suite keeps 67 of them as
fixtures, checked against rizin 0.8.2's listings.

## Status

binform is young (version 0.9) and its API may change. What it does not yet
read is in [docs/limitations.md](docs/limitations.md). Bug reports with
samples help most; see [CONTRIBUTING.md](CONTRIBUTING.md). Apache-2.0.
