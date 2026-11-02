# TODO

## The newer instruction sets

32-bit Arm, MIPS, PowerPC, s390x, SPARC and SuperH decode control flow
only. Next:

- **Jump tables:** Arm reads `tbb`/`tbh`, `addls pc, pc, rN, lsl #2` and
  `ldrls pc, [pc, rN, lsl #2]` when the `cmp` that bounds them sits right
  before (every other Arm instruction forgets all registers). s390x reads
  GCC's `clijh; risbgn; larl; lg; b 0(%rX,%rT)`, and MIPS GCC's PIC form
  (`sltiu; ld page(gp); daddiu; dsll; daddu; ld; daddu gp; jr`, with `_gp`
  in `$gp` or a register computed from `$t9`); 70 of the 75 in
  `libe_sqlite3-linux-mips64.so` resolve. Left: MIPS tables bounded on a
  value reloaded from memory, non-PIC MIPS (`lui; addiu` tables, written
  but untested on a sample), and Thumb-1's `add pc, rm` tables (GCC's
  `__gnu_thumb1_case_*` helpers). SPARC reads GCC's tables (from the GOT
  pointer its PC thunk sets) and Sun Studio's (from `rd %pc`); the few left
  keep their base in a stack slot.
- **Objects:** `relocate` links calls on every set but SuperH. MIPS
  position-independent objects call through `$t9`; their `R_MIPS_JALR`
  hints turn the `jalr`/`jr` into a direct `jal`/`j`, but the `$gp`
  arithmetic (`GOT16`/`LO16`, `CALL16`) is not applied, so any other use of
  a GOT entry stays unresolved.
- **Imports:** SuperH and MIPS PLT stubs (MIPS `-mplt` executables) are
  seeded by the header only; their layouts vary by ABI.
  MIPS GOT calls (`lw $t9, n(rX); jalr $t9`) are read when the load is
  right before the call, and GCC's local form (`ld $t9, %got_page(f)($gp);
  daddiu $t9, $t9, %got_ofst(f)`) when the GOT is in the file.
- **Not read:** big-endian Arm and SuperH, 31-bit s390,
  `.ARM.exidx` unwind entries, and LSDAs on big-endian sets
  (`eh::landing_pads` reads little-endian).
- **MIPS16e:** OpenWrt builds its MIPS packages as MIPS16e (`e_flags` has
  `EF_MIPS_ARCH_ASE_M16`; functions at odd addresses, as Thumb's are), which
  neither funktion nor rizin decodes: OpenWrt 24.10's `busybox` and
  `libsqlite3` for `mips_24kc` come out as a few dozen functions with
  thousands of unresolved jumps.
- **PowerPC** (ELF: 32-bit big-endian, 64-bit ELFv1 and ELFv2) decodes
  branches, `blr`/`bctr` and their linking forms, `.opd` descriptors,
  ELFv2 global entries, addresses built with `lis; addi` (as pointers, in
  32-bit code), and GCC's TOC-relative tables (`bot-ppc-static`,
  `bot-ppc64-elfv1`, `ppc64le-static`; `jq` 1.8.1 covers 92% 32-bit and
  91% `ppc64el`). Left: PLT and glink stubs as imports (ELFv1's `ld r12,
  n(r2); mtctr r12; bctr` reads as unresolved), 32-bit PIC tables (169
  unresolved in `jq`), Go's ppc64 code (`ppc64/bad-154c...` covers 76%),
  32-bit little-endian PowerPC, and Power10 prefixed instructions.
- **Not supported at all:** AIX (XCOFF).

- **From the exotic-binaries survey** (`C:\data\exotic_binaries`, all
  hostile: parse only):
  - SuperH static bots now cover 70-88% (`bot-sh-uclibc-static`: 77%).
    What remains: code reached only through tables and pointers kept
    outside literal pools.
  - Packed and encrypted code: the sweep now skips kilobytes of
    near-random bytes (`bot-s390x-static-pie`, whose `.text` is mostly an
    encrypted payload: 1070 invalid down to 50). Such files cover little,
    as they should; unpacking them is out of scope.
  - MIPS Release 6 (`Arch::MipsR6` and kin, from `e_flags`) decodes
    compact branches, `jic`/`jialc`, `jalr $zero`, `aui` and `lsa`, and
    bounds tables by compact compares (`r6-mipsel-static`). `jq` 1.8.1's
    R6 builds now cover what its other MIPS builds do (90% 32-bit, 84%
    64-bit). Not yet: R6's PC-relative loads (`lwpc`, `auipc`,
    `aluipc`) as table addresses.
  - Windows CE on Arm (`bot-wince-arm`, `bot-wince-thumb`) is read:
    `.pdata` seeds and extents, literal-loaded import stubs, ARMv4
    `mov lr, pc` calls. Thumb functions in such files (a clear 32-bit flag
    in `.pdata`) are untested: no sample has any. One sample
    (`pe-arm/bad-47897`) embeds x86 code in `.text` that `.pdata` points
    into.
  - The small ARMNT DLLs with no functions have no code: resource-only
    (MUI) DLLs, API-set forwarders, IL-only and MDIL assemblies.
  - Packed MIPS bots (no section headers, UPX-style stubs) cover under
    35%; unpacking is out of scope.

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
