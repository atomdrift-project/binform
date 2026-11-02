# TODO

## More instruction sets

`object::image` returns `Error::Arch` for 32-bit Arm, MIPS, SuperH, s390
and SPARC. Each needs a flow decoder like `arm64.rs` (length, branches,
calls, returns, indirect jumps; no jump-table notes at first):

- 32-bit Arm: A32 and Thumb. The mode comes from an address's low bit
  (symbols, the entry point, `blx`); A32 reads PC as the instruction + 8,
  Thumb as + 4. Conditional returns and the inline `ldr pc, [pc, rN, lsl
  #2]` switch table need an instruction that may also fall through (an
  `Insn` flag the walk honours).
- MIPS, SPARC, SuperH: branch delay slots. Treat a branch and its slot as
  one instruction (the branch's length covers the slot), so a call returns
  past the slot.
- s390: 2-, 4- and 6-byte instructions, length from the first byte's top
  two bits; big-endian.
- Big-endian MIPS and SPARC: the readers above already take a byte order;
  `Memory::read` (jump tables) is little-endian only.

Check each against rizin on Go builds of the traits-dev `does-nothing`
program (`GOARCH=arm`, `mips`, `mipsle`, `mips64`, `s390x`); SuperH and
SPARC have no Go port, so hand-assembled tests in `tests/synthetic.rs`.

## Other open items

- **.NET:** `funktion::cil::body` measures CIL method bodies but filefacts
  does not call it yet; wiring it in adds .NET CFG metrics (possible new
  trait hits), so it needs a corpus A/B first.
- **Integration:** stng/filefacts decide when to fall back to rizin, from
  `Recovery` (`code`, `covered`, `invalid`, `unresolved`, `truncated`) and
  `object::Error`. Before dropping rizin for packed files, run a trait-diff
  A/B through scan's normal pipeline.
- **Known misses:** `main` in i386/A64 PIE (loaded through the GOT), musl's
  `_start_c`, and the PE x86 start-up patterns; GCC `.cold` fragments count
  as functions of their own; Go's `runtime.debugCallV2` code after a `brk`
  (reached only by a debugger); jump tables whose base register goes through
  a stack spill (i386 PIC).
