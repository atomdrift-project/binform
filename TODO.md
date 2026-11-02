# TODO

## The newer instruction sets

32-bit Arm, MIPS, s390x, SPARC and SuperH decode control flow only. Next:

- **Jump tables:** the new decoders emit no `Note`s, so Thumb `tbb`/`tbh`,
  the A32 `ldrls pc, [pc, rN, lsl #2]` table, and MIPS/s390x `jr`/`br`
  through a loaded table stay unresolved. In GCC Thumb-2 sqlite
  (`libe_sqlite3-linux-arm.so`) they hold coverage to about 80%.
- **Objects:** `relocate` links only x86, x86-64 and A64. Arm (`CALL`,
  `JUMP24`, `THM_CALL`), MIPS (`26`), s390x (`PLT32DBL`) and SPARC
  (`WDISP30`) objects are laid out but their calls not linked.
- **Imports:** MIPS calls through the GOT (`lw t9, n(gp); jalr t9`) with
  slots named by `DT_MIPS_GOTSYM`, not relocations; SPARC, SuperH and MIPS
  PLT stubs are seeded by the header only (their layouts vary by ABI).
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
