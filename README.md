# funktion

funktion recovers functions from machine code: where each one starts and
ends, its basic blocks, its cyclomatic complexity, and the calls and jumps it
makes. It is a pure-Rust library with no `unsafe`, no subprocesses, and no
I/O: recovery is a function of its input, never panics, and bounds its work by
configurable `Limits`, because the input is assumed hostile.

It covers x86/x86-64, Arm/Thumb, AArch64, MIPS, PowerPC, RISC-V, LoongArch,
s390x, SPARC, SuperH, m68k, OpenRISC, MicroBlaze, ARC, C-SKY and Xtensa, plus
CIL method bodies for .NET. Images come from ELF, PE and Mach-O (the default
`object` feature), or callers with their own parser can fill in an `Image`
directly.

```rust
let bytes = std::fs::read("a.out")?;
let image = funktion::object::image(&bytes)?;
for f in funktion::recover(&image).functions {
    println!("{:#x} {} blocks, complexity {}", f.entry, f.blocks, f.complexity);
}
```

## Where it fits

funktion is part of the [atomdrift project](https://github.com/atomdrift-project),
alongside two tools that today shell out to [rizin](https://rizin.re) for the
same answers:

- **[filefacts](https://github.com/atomdrift-project/filefacts)** turns
  files into security-relevant facts. It runs rizin for symbol recovery and
  CFG metrics on stripped binaries; funktion supplies those metrics
  (function counts, complexity, blocks, calls) in-process, without a
  subprocess or timeout.
- **[stng](https://github.com/atomdrift-project/stng)** extracts strings
  for malware analysis. It uses function boundaries to place strings and
  find stack strings, which funktion provides without rizin or radare2
  installed.

Both fall back to rizin when funktion's `Recovery` reports too little code
covered, or too many invalid, unresolved or truncated paths.

## Accuracy

Every fixture in `testdata/` is a real binary checked against rizin: the
`.golden` file lists both tools' blocks and complexity per function, so any
change shows up as a diff (`FUNKTION_BLESS=1 cargo test --test fixtures` to
accept it). `tools/` has `funktion-ab` to compare the two over a corpus, and
`TODO.md` tracks known gaps per instruction set.

Licensed under Apache-2.0.
