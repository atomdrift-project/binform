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
  neither binform nor rizin decodes: OpenWrt 24.10's `busybox` and
  `libsqlite3` for `mips_24kc` come out as a few dozen functions with
  thousands of unresolved jumps.
- **PowerPC** (ELF: 32-bit big-endian, 64-bit ELFv1 and ELFv2) decodes
  branches, `blr`/`bctr` and their linking forms, `.opd` descriptors,
  ELFv2 global entries, addresses built with `lis; addi` (as pointers, in
  32-bit code), GCC's TOC-relative tables, and import stubs that load
  their slot from a known address (`ld r12, n(r2); mtctr r12; bctr`, `lis;
  lwz; mtctr; bctr`). 32-bit PIC code's GOT pointer (`bcl 20, 31, $+4;
  mflr r30`) is carried across blocks, and a jump table's address read
  from its GOT slot (or the slot's `RELATIVE` relocation); glibc's
  two-level `vfprintf` tables (a byte map, then `add; lwz n(rX)`) resolve
  too. An unbounded table stops at a target past another function's
  start (`bot-ppc-static`, `bot-ppc64-elfv1`, `ppc64le-static`,
  `ppc-pie`; `jq` 1.8.1 covers 96% 32-bit, with 106 unresolved jumps,
  mostly calls through pointers, and 91% `ppc64el`, with 11). `lr` and
  `ctr` travel through the tracker, so musl's `bl 1f; .long f - .; 1:
  mflr r6; lwz; add; mtctr r4; mr r4, r5; bctrl` calls `f`. Go's ppc64
  code covers 98% (`ppc64/bad-154c...`, once its Go 1.18 `.gopclntab`
  was read: the 1.16 and 1.18 magic numbers had been swapped, which also
  cost `s390x/pkg-esbuild` and `mips/pkg-turbo` a fifth of their code).
  Power10's eight-byte prefixed instructions decode, with `pla` addresses
  and `pld` GOT slots PC-relative (`ppc64le-power10-pie`). Left: 32-bit
  little-endian PowerPC (no sample), and the data word after the 64-bit
  call to musl's `_start_c`, which reads as an invalid instruction: its
  `__libc_start_main` reaches the second stage through an opaque register
  (`stage2(main, argc, argv)`), so the walk cannot tell it never returns.
- **Register jumps and calls to known addresses** (every set): a jump
  through a register the tracker holds a code address in is a tail call
  (s390x `larl; br`, MIPS `lui; addiu; jr`, SuperH literal-pool `jmp`,
  Go's `reflect.call` dispatch); PowerPC's `bctrl` likewise calls it.
  Other sets' register calls (`jalr`, `blx`, `call rax`) still decode as
  `CallIndirect`, with no register to look up.
- **RISC-V** (ELF, RV32 and RV64, with or without compressed
  instructions) decodes `jal`/`jalr` (calls through `ra` or `t0`, returns,
  `auipc; jalr` far calls), branches, `auipc; addi` and `lui; addi`
  addresses, `gp`-relative addresses (from `__global_pointer$`, or the
  `_start` code that sets `gp`), PLT stubs (`auipc t3; ld t3, n(t3); jalr
  t1, t3`), and jump tables bounded by `bltu`/`bgeu` against a constant,
  including GCC's RV64 zero-extended index (`slli 32; srli 30`) and Zba's
  `sh*add`, `slli.uw` and `zext.w` (`rv64-pie`; `jq` 1.8.1 covers 99%,
  with 9564 cases in its tables and 165 unresolved jumps, mostly
  oniguruma's dispatch through pointers loaded from structs; Go and the
  bots 87-98%). Objects are linked, relaxation's branch relocations and
  `ADD32`/`SUB32` table entries included (`calls-riscv64.o`,
  `rv64-switch.o`; the corpus's Go race `.syso` drops from 3731
  "functions", one per unlinked call, to 758). Tables of sign-extended
  32-bit absolute addresses (`lw; jr`, code linked below 2 GiB) resolve
  on every 64-bit set. Rizin finds next to nothing on RISC-V to compare
  against (`aa` keeps only the entry point). PLT stubs are seeded from
  the section's fixed layout (a 32-byte header, 16 bytes per import).
- **LoongArch** (ELF, LA64 only; 32-bit LoongArch is refused) decodes `b`,
  `bl`, the conditional branches, `jirl` (`jr ra` returns, linking `ra`
  calls), `pcaddu18i; jirl` far calls, the constants `pcaddi`,
  `pcalau12i`, `pcaddu12i`, `lu12i.w`/`ori`/`lu32i.d`/`lu52i.d` and
  `addi` build, PLT stubs and GOT calls through a slot, and jump tables
  bounded by `bltu`/`bgeu` (GCC's `alsl.d; ldptr.d; jr`, absolute; LLVM's
  `ldx.w; add.d; jr`, relative). The vector extensions decode as
  instructions that may write an integer register. Only a complete
  address (not a `pcalau12i` page) counts as a function pointer. Objects
  are linked (`B16`/`B21`/`B26`, `CALL36`, `PCALA`, GOT for imports,
  `32_PCREL`, `ADD`/`SUB`). Fixtures: `la64-pie`, `calls-loongarch64.o`,
  `la64-switch.o`; the corpus bots cover 95%, its Go race `.syso` 91%
  (754 functions, from 3638 unlinked). Rizin's analysis finds only the
  entry point.
- **m68k** (ELF, the 68000 family; the corpus is all 68020) decodes every
  integer instruction's length (checked against rizin over a bot's
  `.text`: 12399 boundaries agree; rizin rejects the 68020's `bsr.l`,
  `extb.l`, bit fields and 32-bit `mul`/`div`, which binform reads), the
  FPU's, `bsr`/`jsr`/`bra`/`jmp`/`Bcc`/`DBcc`, `jsr (An)` through a
  register `lea` set, `jmp ([d, pc])` through a slot (a PLT stub), and
  GCC's tables (`move.w (2, pc, d0.l*2), d0; jmp (2, pc, d0.w)`), bounded
  in a register or in memory (`cmp.l 12(a3), d1`, then a reload of
  `12(a3)`). Addresses pushed (`pea main.l`) or stored (`move.l #f, ...`)
  are function pointers: that is how start-up code passes `main` and how
  the bots register their routines (`bot-m68k-static`; the stripped
  bots cover 91-98%, the unstripped 99%). Not yet: PLT seeding, object
  relocation, and `main` as `Found::MAIN` (arguments go on the stack). One
  corpus file (`m68k/bad-0070230...`) has four bytes of every 32 in
  `.text` overwritten with `00 00 00 02`, and false section headers: it
  covers 46%.
- **OpenRISC 1000** (ELF, `or1k`, big-endian, delay slots) decodes
  `l.j`/`l.jal`/`l.bf`/`l.bnf`, `l.jr`/`l.jalr` through register
  constants (`l.movhi; l.ori`) and loaded slots, `l.trap` and `l.rfe`.
  Start-up code's `l.jal` to just past its slot (a PC read) or over a
  word of data is a jump, not a call. Integers built from `r0`
  (`l.ori rd, r0, n`) are no addresses; ones built like addresses
  (`l.movhi; l.ori`: 100000 is `0x186a0`) are kept only where no
  explored function covers them (see Pointers in data). The corpus bots
  cover 98% with no invalid instructions (`bot-openrisc-static`); the
  five unresolved jumps in each are tail calls through loaded function
  pointers. No jump tables seen yet (GCC emitted none in these), and no
  PLT or object relocations. Rizin 0.8.2 cannot decode OpenRISC.
- **MicroBlaze** (ELF, either byte order; the corpus is big-endian)
  decodes the `imm` prefix that widens the next immediate (addresses are
  `imm hi; addik rD, r0, lo`; an immediate it did not widen is an
  integer), delay slots only on the `D` forms, `brlid`/`brald` calls
  (through register constants and loaded slots), `rtsd r15, 8`, and
  `brki r14, 8` (the system call, which returns). GCC's tables, built
  without a barrel shifter, scale by adding the case value to itself
  (`cmpu r18, r4, r22; bltid r18, default; addk r3, r4, r4; addk r3, r3,
  r3; imm; addik r3, r3, table; lwi r3, r3, 0; bra r3`). PIC code finds
  the GOT with `mfs r20, rpc`; in a static link each slot holds its
  target, which the call goes to (as MIPS GOT slots do). The five
  table-using bots cover their `.text` to within 8 bytes, with 164-178
  cases and nothing unresolved (`bot-microblaze-static`); the PIC one
  97% (`bot-microblaze-pic`). An `imm` applies only to the instruction
  at the address after it: the stub check decodes callees mid-walk. Not
  yet: PLT stubs, object relocations, PIC jump tables (none seen). Rizin
  0.8.2 cannot analyze MicroBlaze.
- **ARC** (ELF, little-endian: ARCompact/ARC700 and ARCv2/HS) decodes
  16- and 32-bit instructions with their `limm`s (lengths agree with
  rizin over a bot's whole `.text`), `.d` delay slots, `b`/`bl`/`Bcc`,
  `BRcc`/`BBITn` (a bound when unsigned against a constant, even from a
  delay slot), `j`/`jl` through registers, constants and slots, returns
  (`j_s [blink]`, conditional `jeq_s [blink]`, ARCv2's `leave_s`), `lp`,
  and `flag 1` (halt). GCC's tables: absolute (`ld.as r0, [table, r0];
  j_s [r0]`) and relative to `pcl` (`ldw.as`/`ldb_s` entries, then `add_s
  rX, rX, pcl`); ARCv2's `bi`/`bih` index a run of branches (untested on
  a sample). Entries into the `-mmillicode` epilogue
  (`__ld_r13_to_rN_ret`, jumped to) are functions; without that every
  caller absorbed it. `pcl`-relative addresses are held but are no
  function pointers (they point at data kept in `.text`); `st limm, [..]`
  stores one. The ARC700 bots cover 86-96%, the ARCv2 ones 86-99%
  (`bot-arc-static`, `bot-arcv2-dynamic`, whose ARCv2 PLT is seeded).
  Left: a bound set in the delay slot of a call to `__st_r13_to_rN`
  (`bl.d __st_r13_to_r16; cmp r0, 240`) is lost at the call (the
  millicode keeps `r0` and the flags), so the `bad-0073ff` family resolves
  no cases; no ARCompact PLT, big-endian ARC or object relocations.
  Rizin 0.8.2 decodes ARCompact only, and reads ARCv2 as x86.
- **C-SKY** (ELF, ABIv1: CK510/CK610, little-endian) decodes the 16-bit
  set: `br`/`bt`/`bf`/`bsr`, `jmp`/`jsr` through registers held
  constant, `jmpi`/`jsri` through pool words, `rts`/`rte`, and GCC's trap
  (`bsr .`). Literal pools sit after each function's last jump: the
  sweep steps over the words `lrw`/`jmpi`/`jsri` read, and no function
  inferred from a call or an address starts in one. Code that follows
  an unconditional end and pools, and starts with `subi r0, n` or `stm`,
  starts a function (uncalled ones in a static binary). PIC code's GOT
  base (`bsr 1f; 1: lrw r14, [offset]; addu r14, r15`) is learned once
  and held in `r14` at every block start, so `lrw r7, [offset]; addu r7,
  r14; jsr r7` resolves. A pool word the next instruction adds to the PC
  (the GOT base, a far branch: `bsr 1f; lrw r1, [offset]; addu r1, r15;
  ...; jmp r1`) is an offset, not an address. A far branch's
  `subi r0, 8; stw r15, (r0, 0); bsr 1f` is no frame. An address only
  taken must be word-aligned, as GCC's functions are. On the bots with
  symbols (blanked), every function found is a symbol's and 11 of 463 are
  missed (uncalled leaves such as `__sigdelset`, `call_frame_dummy`);
  coverage is 88-90% (the rest is pools), one invalid each (a `bkpt`
  trap), and the only unresolved jump is `_dl_linux_resolve`'s
  (`bot-csky-static`). Left: ABIv2 (CK807/CK810, 32-bit instructions),
  which no corpus sample uses; GCC's jump tables were not seen (switches
  compile to compare chains). Rizin 0.8.2 has no C-SKY support.
- **Xtensa** (ELF, little-endian, windowed ABI) decodes the two- and
  three-byte set: PC-relative `call0`/`call4`/`call8`/`call12` and `j`,
  `callx`/`jx`/`ret`/`retw` through registers, the twelve- and eight-bit
  `beqz`/`beqi`/`beq` branches and `loop`, `entry` (a frame), and `l32r`,
  which loads a word from a literal pool placed *before* it. A pass over
  each segment finds those pool words (every `l32r`'s target) so the sweep
  steps over them as data; `l32r` of a callee's address then `callx`
  resolves to a call. Every function opens with `entry`, so the sweep
  seeds each one it finds (word-aligned), and a swept call whose target is
  no frame is a mis-decoded pool word, dropped. `l32i` notes its load, so
  a GOT read or a jump table through a known address resolves. Eight-bit
  branch offsets are signed (`loop`'s alone is not), and `ill` after a
  call that never returns is a stop. On the bot with symbols, all 494 are
  found, plus 5 `entry` routines with no symbol (`lib2funcs.S`), 0
  invalid, 90% covered (the rest is pools); the stripped bot 86%, the
  dynamic one all 42 and 80% (`bot-xtensa-dynamic`; rizin 0.8.2 cannot
  decode `beqz.n`/`bnez.n` and loses sync after each). Left:
  the `.plt` stub (`l32r a8, slot; l32i.n a8, a8, 0; jx a8`) is a double
  indirection the thunk walk does not yet fold, so imports are listed but
  their stubs are unlinked; switch tables through `addx4; l32i; jx` leave
  a handful of jumps unresolved; no call0 ABI or big-endian Xtensa.
- **Not supported at all:** AIX (XCOFF), and these corpus sets:
  Nios II, IA-64, MIPS-FPU and PowerPC PE files, and big-endian M*Core
  and eBPF. (Little-endian M*Core decodes as C-SKY ABIv1, 79% of
  `bot-mcore-static`; eBPF objects as `isa/bpf.rs`, whole programs.)

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

- **Pointers in data:** once every other start is explored, a word in a
  segment that is not code, address-aligned, that points at code no
  function covers and that sets up a frame there (`starts_frame`) is a
  function's address (callbacks a stripped static binary keeps in tables:
  musl's stdio callbacks in `stdout`'s `FILE`, a bot's table of attack
  routines, Rust vtables: `s390x/pkg-binding-s390x-rspack` 60% to 68%).
  So are the targets of `RELATIVE` relocations. Sets without
  `starts_frame` (MIPS, SPARC) gain nothing, and 32-bit Arm is left out:
  a pointer to Thumb code carries bit 0, so an even word into Thumb code
  is no function's address.
  Addresses code builds (`Note::Address` on sets that note pointers)
  wait until the queue empties too, and one that falls inside code an
  explored function covers is dropped unless code jumps there or it sets
  up a frame: an integer that happens to look like an address
  (`bot-openrisc-static`; on `bot-ppc-static` this lets one function
  grow to the 60 blocks rizin finds). SuperH's `starts_frame` accepts a
  leaf that pushes two registers or more.

- **Calls that never return** are known by name, and, where what follows
  a call fails to decode within two instructions, by a walk of the callee
  that finds no way back (traps, loops, calls that never return; anything
  indirect may return). rizin infers nothing more, so binform applies the
  walk only there: inferring every stripped `abort` wrapper would end its
  callers' blocks early and cost 72 of `classic-level-darwin.node`'s 1264
  functions their match with rizin.

- **.NET:** CIL method-body measurement left binform (rizin builds no CIL
  graphs). It belongs in filefacts beside `pe/clr`: restore it from
  `src/cil.rs` at funktion commit `bea241f` when wiring it in, after a
  corpus A/B (it adds .NET CFG metrics, so possible new trait hits).
- **Known misses:** `main` in i386/A64 PIE (loaded through the GOT), musl's
  `_start_c`, and the PE x86 start-up patterns; GCC `.cold` fragments count
  as functions of their own; Go's `runtime.debugCallV2` code after a `brk`
  (reached only by a debugger); jump tables whose base register goes through
  a stack spill (i386 PIC).

## Replacing rizin in filefacts and stng

The line (README, "The line"): binform reports what code mechanically
does, per instruction set; filefacts and stng decide what it means. Both
tools decode instructions themselves today (filefacts: ~1600 lines of
iced-x86 and hand-written AArch64 for syscalls and API hashing; stng:
~4000 lines for stack strings, `lea`/`adrp` strings and its XOR
decoders), so the work is as much moving decoding here as dropping rizin.
In scan's pipeline stng already runs without rizin; only the stng CLI
(`src/cli/rizin.rs`) calls it.

1. **Names on functions and refs.** `Function` carries no name; rizin's
   `sym.imp.*`/`fcn.*` name the call-site facts filefacts emits. Add the
   symbol, export or stub import a function is known by, and a helper
   that names a `Ref`'s target (an import slot, a stub, a named function).
   Document the complexity formula (edges − blocks + 2·exits) so filefacts
   can state what its metrics mean, and `Limits` presets for
   latency-sensitive callers (binform is bounded and in-process, so the
   timeout, retry and process-group machinery go with rizin).
2. **filefacts primary path.** A tool-agnostic function table (entry,
   size, complexity, blocks, call sites) that both `RizinRecovery` and a
   binform adapter fill; `apply_inner`, the metrics and
   `pe/api_hash.rs` (`function_ranges`, `direct_call_edges`) read only
   the table. **Done, and rizin is gone from extraction:** binform runs
   on every binary with no function inventory and fills the import,
   export and section views goblin left empty; nothing falls back
   (see PLAN step 6). Cache key: binform's policy alone. **rizin shim
   deleted. Done:** `filefacts::rizin` is gone (module, `rizin.rs`, every
   `OpenOptions::rizin*` method, `rizin_fingerprint`→`recovery_fingerprint`,
   `rizin_recovery_incomplete`→`recovery_incomplete`), and cleave is fully
   severed — no `rizin`/`skip_rizin`/`rizin_timeout` settings, no
   `kill_all_rizin_groups`, the archive-member rizin-skip subsystem removed,
   `--disable rizin` kept only as an accepted-but-ignored flag. Verified by a
   temporary local `[patch]` (reverted): filefacts and cleave build and test
   green, with zero new regressions (the one recovery-dependent test,
   cleave's `direct_syscall_projection`, relied on rizin's linear sweep of a
   headerless section and was made realistic — see
   `memory/rizin-sever-headerless-recovery-gap`). Left: cleave consumes
   filefacts by git pin, so bump that pin after filefacts is pushed.
   **Function inventory now prefers binform over goblin. Done:** the ELF
   extractor no longer lets a bare `.symtab` stand in ahead of binform (that
   was the last goblin-preferred-over-binform leg, a vestige of the rizin
   decision). binform is primary — it names functions from the symbol-table
   seeds it reads and adds complexity and a call graph a `.symtab` cannot —
   and the symtab fallback (`static_function_fallback`, coverage heuristic and
   `required` param dropped) stands in only when binform recovered nothing (an
   undecoded arch) with no pclntab. Go's pclntab still pre-empts binform (its
   generic recovery over-extends Go `.text`), and .NET/CLR likewise; PE and
   Mach-O were already binform-primary (no symtab→Function path). Shifts
   `binary.*_function_count`/complexity for unstripped non-Go binaries —
   recalibrate in the A/B (step 3). binform's
   own ELF/PE/Mach-O reader may disagree with goblin on
   hostile files: log the disagreements, and consider filling `Binary`
   from goblin later. **Universal slice: done** — binform ranks x86-64,
   arm64, i386 (`preferred_slice`), the slice rizin read on the x86-64
   scanners, deterministic on any host. **rizin parity: done** — the files
   rizin covered and binform did not were eBPF and M*Core (now decoded) and
   ARMNT forwarder DLLs (data rizin took for code; nothing to match), and
   the native fill skips empty import/export names as rizin's did. Also: `pe.rizin_importless_*` metric key
   names still say "rizin" — a schema-versioned rename (key catalog + cleave
   consumers + cache key) left for a deliberate pass.
3. **A/B.** `binform-ab` over the corpus for the aggregates, then a
   trait diff through scan's normal pipeline. Block counts differ from
   rizin's and are often more accurate (and rizin cannot decode OpenRISC,
   MicroBlaze, C-SKY or `beqz.n`), so `binary.avg_complexity`,
   `huge/tiny/leaf_function_count` and kin will move; recalibrate the
   traits that depend on them, and set the fallback thresholds from the
   share of files that would still reach rizin and why.
4. **Call and syscall facts — `binform::calls`. Done in binform.**
   `calls(bin, fns)` yields every call and syscall site in the recovered
   functions with its arguments' values (a constant, or a pointer and the
   bytes behind it, from the file or a per-function stack model). Which
   register holds the syscall number and arguments is ABI knowledge in
   `src/calls/{x86,arm}.rs`; `Binary::syscall` names a number from a
   per-arch, per-OS table (`src/syscalls.rs`, generated by
   `tools/syscalls.py` from the `libc` crate). x86, x86-64 and 32-bit Arm
   track arguments; other sets yield no calls yet. Validated against rizin
   `/as` (kimwolf's `socket`/`connect` with the stack sockaddr; brickstorm's
   52 syscalls with no unaligned false positives).
   - **`filefacts/src/formats/elf/syscalls.rs` is on `calls`. Done.** One
     binform recovery per ELF now feeds both the function inventory and the
     syscall sites; `functions::recover` projects the sites into
     `SyscallFact`s (name via `Binary::syscall`) while the `Binary` is in
     scope, and `syscalls::emit` turns them into `elf.syscalls_direct` with
     a `decoded` sockaddr field and `via` for a libc `syscall()` wrapper.
     The old iced sweep, AArch64 window and hand-written number tables are
     gone; extraction now covers x86, x86-64, Arm and AArch64. kimwolf's
     `connect` resolves to `45.139.197.87:8082`. **Done:** decoded
     destinations are emitted as the `elf.network_endpoints` IOC
     (ip/port/offset/syscall/via, with `elf.network_endpoint_count`), and the
     libc `connect()` call path projects as `via: "connect"` with the number
     from `Binary::syscall_number("connect")` (the inverse table lookup now in
     binform). `binform::calls` dedupes by address (overlapping recovered
     functions were emitting one site many times).

   - **Spilled pointers + connect-wrapper attribution. Done.** The value
     model (`calls/state.rs`) now remembers a symbolic value spilled to the
     frame (`store_slot`/`load_slot`), so a pointer parked on the stack and
     reloaded into an argument register survives; the x86 tracker addresses
     the frame through any base register holding a stack pointer (`rbp`
     frames, not just `rsp`) and restores a reloaded spill. filefacts
     attributes a direct call to a thin `connect` syscall wrapper (a small
     function that issues the connect syscall) as a `connect` with the
     caller's arguments (`via: "wrapper"`), using `Binary::syscall_number`.
     Regression test: `x86_64_connect_sockaddr_spilled_and_reloaded`.

   - **A/B findings (`C:\data\gauntlet`, 61 ELF samples) — open.**
     - **sockaddr C2 recall is still ≈ 0% end-to-end, and the cause is
       inter-procedural.** The connect site itself is glibc's wrapper
       (`mov eax, 42; syscall`), now correctly attributed to the caller with
       its `addrlen` resolved — but the `sockaddr` pointer at the caller is a
       *function parameter* (`mov [rbp-0x720], rdi`), built in a higher frame.
       Intra-procedural tracking, spills included, cannot reach it. Closing
       this needs inter-procedural argument propagation (follow a value into a
       callee / up from a caller), a larger analysis with real false-IOC risk;
       decide whether it is worth it before building. The decode does fire
       when the sockaddr is built and used within one function (the kimwolf
       and x86-64 spill tests).
     - **Go/ARM syscall false positives. Fixed.** The Arm/AArch64 `svc` match
       now requires a zero comment (`svc #0`), which is what Linux's EABI
       always issues; a non-zero immediate is data sharing the opcode bits.
       This cut the 8.8 MB Go/ARM sample from ~70k false `svc` to 42, and
       another Arm sample from 127 to 0 (it has no `svc #0` at all, which rizin
       confirms), while the real Arm samples (tadashi) and the kimwolf tests
       keep their syscalls. The underlying recovery over-extension on Go
       `.text` remains (mega-functions), but it no longer manufactures
       syscalls. Regression: `arm_svc_requires_a_zero_comment`.
   - Then `pe/api_hash.rs` takes its call graph from `Function`/`Ref`;
     its PEB and export-walk shape detectors stay, optionally run over
     binform's instructions instead of a sweep.
5. **stng CLI drops rizin. Done.** `izzj`/`isj`/`iSj` gone (stng's
   extractor, goblin symbols and goblin sections cover them); XOR decoding
   is aimed at stng's native string extents; the connect pass is dropped
   (it belongs in `calls` → filefacts → cleave). `cli/rizin.rs`,
   `ExternalHints` and the `--no-rizin`/`dirs` machinery are removed.
6. **Later, in stng:** `instr/amd64.rs` and `instr/arm64.rs` take their
   addresses from binform (every instruction set, correct boundaries)
   and keep the pointer/length pairing; `stack_strings.rs` (a 64-bit
   iced sweep) moves to stack-store facts once they exist. The AArch64
   caller-state recognizer, `xor/arm64_stack.rs`, `xor/pointer/arm64/*`
   and the `xor/pe_decoder.rs` interpreter stay: XOR- and
   string-specific. `fileid/shellcode.rs`'s GetPC byte checks stay in
   filefacts: a few byte reads at offset 0 do not justify recovery.

Order: 1–3, 5 and 4's filefacts step are done. Next: the two A/B findings
above (sockaddr arg recall across joins; Go/ARM `svc` false positives), then
4's `pe/api_hash.rs`, then 6.
