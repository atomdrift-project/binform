# binform

![binform logo](docs/logo-small.png)

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

We started with goblin, but it was not lenient enough for malformed
malware: it rejects a whole file over one bad table, 23 of the 582 in our
corpus. We moved to rizin, which does far more, but its analysis of the
same corpus took 65 times as long. binform is the result. It reads what it
can of a damaged file, and does less on purpose: it says what the code
does and leaves what that means to the caller.

rizin is the yardstick: `tools/binform-ab` has compared the two on thousands
of binaries, and the fixtures are checked against rizin 0.8.2's listings.

## Status

binform is young (version 0.9) and its API may change. What it does not yet
read is in [docs/limitations.md](docs/limitations.md). Bug reports with
samples help most; see [CONTRIBUTING.md](CONTRIBUTING.md). Apache-2.0.
