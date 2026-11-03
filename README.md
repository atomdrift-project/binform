# binform

binform recovers functions from machine code: where each one starts and
ends, its basic blocks, its cyclomatic complexity, and the calls and jumps it
makes. It is a pure-Rust library with no `unsafe`, no subprocesses, and no
I/O: recovery is a function of its input, never panics, and bounds its work by
configurable `Limits`, because the input is assumed hostile.

It covers x86/x86-64, Arm/Thumb, AArch64, MIPS, PowerPC, RISC-V, LoongArch,
s390x, SPARC, SuperH, m68k, OpenRISC, MicroBlaze, ARC, C-SKY and Xtensa, in
ELF, PE and Mach-O binaries. The API is three pure functions over plain
structs, and a caller pays only for what it calls: `parse` reads the
headers into a `Binary` (format, entry point, sections, imports and
exports, by rizin's rules), `functions` recovers its functions, and
`calls` yields every call and syscall site (one per address) with the values
its arguments carry. `Binary::syscall` names a syscall number for the
binary's OS and architecture, and `Binary::syscall_number` is its inverse —
the number a libc wrapper such as `connect` issues. A binary of an
instruction set binform does not decode still parses: it has a layout, no
`arch`, and no functions.

```rust
let bytes = std::fs::read("a.out")?;
let bin = binform::parse(&bytes)?;
let funcs = binform::functions(&bin, &binform::Limits::DEFAULT);
for f in &funcs.functions {
    println!("{:#x} {} blocks, complexity {}", f.entry, f.blocks, f.complexity);
}
for call in binform::calls(&bin, &funcs) {
    if let binform::Target::Syscall(n) = call.target {
        println!("{:#x} syscall {:?} {:?}", call.addr, bin.syscall(n), call.args);
    }
}
```

## Where it fits

binform is part of the [atomdrift project](https://github.com/atomdrift-project),
where two tools use it:

- **[filefacts](https://github.com/atomdrift-project/filefacts)** turns
  files into security-relevant facts. On a stripped binary it needs the
  function inventory and CFG metrics (function counts, complexity, blocks,
  calls), the call graph its API-hash detector correlates, and the
  constant arguments at each syscall.
- **[stng](https://github.com/atomdrift-project/stng)** extracts strings
  for malware analysis. It needs the function inventory, and aims its own
  XOR decoding at the string extents it finds natively.

Both shelled out to [rizin](https://rizin.re) for these. Both have moved
off it: filefacts calls binform for every binary without a function
inventory, and for the sections, imports and exports of a PE goblin cannot
read; stng no longer runs rizin at all.

### The line

binform reports what code mechanically does; its callers decide what it
means. Anything that is per-instruction-set decoding work, and gives the
same answer whoever asks, belongs here:

- instruction boundaries, functions, blocks, complexity, calls and jumps;
- the constant that reaches an instruction: an address built into a
  register, the number and arguments at a syscall or call, including the
  bytes behind a pointer argument (a `sockaddr` built on the stack).

Anything that needs domain meaning or emulation stays with the caller:
what a syscall number is called and implies (filefacts' tables and trait
rules), whether bytes are a string, a key or an indicator (stng's
classifiers), a PEB walk or an export-directory hash loop (filefacts'
detectors), an interpreter that follows a decoder loop (stng's).

The test for new code: per-instruction-set work that both tools would
use goes in binform; a detector written against one instruction set with
domain meaning stays with its tool.

## Accuracy

Every fixture in `testdata/` is a real binary checked against rizin: the
`.golden` file lists both tools' blocks and complexity per function, so any
change shows up as a diff (`BINFORM_BLESS=1 cargo test fixtures` to
accept it). `tools/` has `binform-ab` to compare the two over a corpus, and
`TODO.md` tracks known gaps per instruction set.

Licensed under Apache-2.0.
