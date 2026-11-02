# TODO

## The newer instruction sets

32-bit Arm, MIPS, s390x, SPARC and SuperH decode control flow only. Next:

- **Jump tables:** Arm reads `tbb`/`tbh`, `addls pc, pc, rN, lsl #2` and
  `ldrls pc, [pc, rN, lsl #2]` when the `cmp` that bounds them sits right
  before (every other Arm instruction forgets all registers). MIPS
  (`sltiu; lui/addiu; sll; addu; lw; jr`), s390x (`clgfi; sllg; lgf; agr;
  br`) and SPARC tables are still unresolved; no fixture has them yet (Go
  emits tables only on amd64 and arm64), so they need a C build first.
  Thumb-1's `add pc, rm` tables (GCC's `__gnu_thumb1_case_*` helpers) are
  not read either.
- **Objects:** `relocate` links calls on every set but SuperH. MIPS
  position-independent objects call through `$t9`; their `R_MIPS_JALR`
  hints turn the `jalr`/`jr` into a direct `jal`/`j`, but the `$gp`
  arithmetic (`GOT16`/`LO16`, `CALL16`) is not applied, so any other use of
  a GOT entry stays unresolved.
- **Imports:** SPARC, SuperH and MIPS PLT stubs (MIPS `-mplt`
  executables) are seeded by the header only; their layouts vary by ABI.
  MIPS GOT calls (`lw $t9, n(rX); jalr $t9`) are read when the load is
  right before the call; GCC's local form (`lw $t9, %got(f)($gp); addiu
  $t9, $t9, %lo(f)`) is not.
- **Not read:** big-endian Arm and SuperH, 31-bit s390, PE `ARMNT`
  (Thumb-2 Windows), `.ARM.exidx` unwind entries, and LSDAs on big-endian
  sets (`eh::landing_pads` reads little-endian).
- **Go:** calls to `runtime.gopanic`, `runtime.throw` and the like are not
  known to never return (the list is rizin's), so padding after them shows
  as `invalid` on s390x.

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
