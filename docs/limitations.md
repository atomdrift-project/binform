# Known limitations

What binform does not recover, and the heuristics it applies deliberately.
Each statement is about the current code; fixture names refer to files in
`testdata/`, whose notes describe the idioms in more detail.

Where a choice could go either way, binform chooses so that the functions
and blocks it reports agree with what a recursive-descent disassembler
reports. The fixtures compare against a frozen rizin 0.8.2 listing for that
reason (see `testdata/README.md`).

## Not supported

- **Formats:** AIX XCOFF.
- **Instruction sets:** IA-64, big-endian M\*Core, big-endian eBPF,
  big-endian Arm, big-endian SuperH, big-endian ARC, big-endian Xtensa,
  31-bit s390, C-SKY ABIv2 (CK807/CK810), 32-bit LoongArch, MIPS16e, and
  Xtensa's call0 ABI. A file of an unsupported set parses to its layout and
  has no functions.
- **Decoded under another name:** little-endian M\*Core is decoded as C-SKY
  ABIv1 (`bot-mcore-static`); Windows CE MIPS and Windows NT little-endian
  PowerPC PE files as MIPS and PowerPC (`wince-mips.exe`, `winnt-ppc.exe`).
- **Not read:** `.ARM.exidx` unwind entries.
- **Packed or encrypted code** is not unpacked. The sweep skips runs of
  near-random bytes (byte entropy above what machine code reaches) rather
  than start functions in them (`bot-s390x-static-pie`), so such files cover
  little.

## Cross-cutting

- **Pointers in data.** Once every other start is explored, a word in a
  non-code segment that is address-aligned, points at code no function
  covers, and sets up a frame there (`starts_frame`) is taken as a
  function's address: callbacks a stripped static binary keeps in tables,
  such as musl's stdio callbacks in `stdout`'s `FILE`, or Rust vtables. So
  are the targets of `RELATIVE` relocations. Sets without `starts_frame`
  gain nothing from this. 32-bit Arm is excluded: a pointer to Thumb code
  carries bit 0, so an even word into Thumb code is no function's address.
  SPARC and MIPS frames (`save %sp, -n, %sp`, `addiu $sp, $sp, -n`) vet
  pointers as other sets' frames do, but a jump to such an address is not
  taken as a tail call there, since GCC shrink-wraps the frame past an
  early return (`Decoder::frames_late`).
- **Addresses built in code** (`Note::Address`) are also held until the
  queue empties. One that falls inside code an explored function covers is
  dropped unless code jumps there or it sets up a frame, so an integer that
  looks like an address starts no function (`bot-openrisc-static`). SuperH's
  `starts_frame` accepts a leaf that pushes two or more registers.
- **Register jumps to known addresses.** A jump through a register the
  tracker holds a code address in is a tail call (s390x `larl; br`, MIPS
  `lui; addiu; jr`, SuperH literal-pool `jmp`, Go's `reflect.call`
  dispatch); PowerPC's `bctrl` likewise calls it. Other sets' register calls
  (`jalr`, `blx`, `call rax`) decode as indirect calls with no target.
- **Calls that never return** are known by name and, where what follows a
  call fails to decode within two instructions, by a walk of the callee that
  finds no way back (traps, loops, calls that never return; anything
  indirect is assumed to return). The walk is applied only there: inferring
  every stripped `abort` wrapper would end callers' blocks earlier than a
  reference disassembler does.
- **Tables of 32-bit absolute addresses**, sign-extended (`lw; jr`, code
  linked below 2 GiB), resolve on every 64-bit set.
- **Call and argument values.** `calls` tracks argument values on x86,
  x86-64, 32-bit Arm and A64; other sets yield no calls. Tracking is
  intra-procedural: a pointer passed in as a parameter and built in a
  caller's frame is unknown at the call that uses it. A value spilled to the
  frame and reloaded is kept.
- **Known misses:** `main` in i386 and A64 PIE executables (loaded through
  the GOT); musl's `_start_c`; the PE x86 start-up patterns; GCC `.cold`
  fragments, which count as functions of their own; Go's
  `runtime.debugCallV2` code after a `brk` (reached only by a debugger);
  jump tables whose base register goes through a stack spill (i386 PIC).

## 32-bit Arm

- **Jump tables:** `tbb`/`tbh`, `addls pc, pc, rN, lsl #2` and
  `ldrls pc, [pc, rN, lsl #2]` are read only when the bounding `cmp` sits
  right before them (every other instruction forgets all registers).
  Thumb-1's `add pc, rm` tables (GCC's `__gnu_thumb1_case_*` helpers) are
  not read.
- **Windows CE** (`bot-wince-arm`, `bot-wince-thumb`): `.pdata` seeds and
  extents, literal-loaded import stubs and ARMv4 `mov lr, pc` calls are
  read. Thumb functions in such files (a clear 32-bit flag in `.pdata`) are
  untested: no sample has any.
- **Go on ARMNT:** Go's `windows/arm` port emits A32 code under the ARMNT
  machine, so a Go PE's starts keep bit 0 clear. The sweep does not take a
  call into the other mode (`0xfafafafa` reads as `blx`) or a few bytes
  behind itself (a literal pool's `0xfbfffffc`) as a function start.
- ARMNT DLLs that are resource-only (MUI), API-set forwarders, or IL-only
  and MDIL assemblies have no code and yield no functions.

## MIPS

- **Jump tables:** GCC's PIC form (`sltiu; ld page(gp); daddiu; dsll;
  daddu; ld; daddu gp; jr`, with `_gp` in `$gp` or computed from `$t9`) is
  read; 70 of the 75 in `libe_sqlite3-linux-mips64.so` resolve. Not read:
  tables bounded on a value reloaded from memory. Non-PIC tables (`lui;
  addiu`) are implemented but untested on a sample.
- **Objects:** position-independent objects call through `$t9`;
  `R_MIPS_JALR` turns the `jalr`/`jr` into a direct call or jump, but the
  `$gp` arithmetic (`GOT16`/`LO16`, `CALL16`) is not applied, so any other
  use of a GOT entry stays unresolved.
- **Imports:** `-mplt` PLT stubs are seeded from the header only. GOT calls
  (`lw $t9, n(rX); jalr $t9`) are read when the load is right before the
  call, and GCC's local form (`ld $t9, %got_page(f)($gp); daddiu $t9, $t9,
  %got_ofst(f)`) when the GOT is in the file.
- **Position-independent entries:** functions reached only through
  pointers are seeded from their `$gp` setup: o32's `.cpload` (`lui; addiu;
  addu $gp, $gp, $t9`) as a function's first instruction; n64's (`lui;
  daddu; daddiu`, after the frame) names its entry as `_gp - d`, checked
  against the dynamic table's `_gp` and, in multi-GOT binaries, against the
  values the known functions' setups agree on (`Got::learn`). Multi-GOT n64
  code with no `$gp` setup a known `_gp` names is not found.
- **Reserved encodings:** words pre-Release 6 leaves reserved (unassigned
  SPECIAL, REGIMM and COP1 encodings, shifts with an `rs`, ALU operations
  with a shift amount) are not code, so a walk stops at data kept in `.text`.
- **Go:** `deferreturn` tails (`jal runtime.deferreturn; ...; jr $ra`,
  reached only by panics) lie outside their functions.
- **Release 6** (`r6-mipsel-static`): compact branches, `jic`/`jialc`,
  `jalr $zero`, `aui` and `lsa` decode, and tables are bounded by compact
  compares. R6's PC-relative loads (`lwpc`, `auipc`, `aluipc`) are not read
  as table addresses.
- **MIPS16e** (`EF_MIPS_ARCH_ASE_M16`, functions at odd addresses) is not
  decoded; OpenWrt's MIPS packages are built this way.
- Packed MIPS binaries (no section headers, UPX-style stubs) are not
  unpacked.

## PowerPC

ELF 32-bit big-endian, 64-bit ELFv1 and ELFv2, and little-endian 32-bit PE.

- Read: branches, `blr`/`bctr` and their linking forms, `.opd` descriptors,
  ELFv2 global entries, `lis; addi` addresses (as pointers, in 32-bit code),
  GCC's TOC-relative tables, and import stubs that load their slot from a
  known address (`ld r12, n(r2); mtctr r12; bctr`, `lis; lwz; mtctr; bctr`).
- 32-bit PIC code's GOT pointer (`bcl 20, 31, $+4; mflr r30`) is carried
  across blocks, and a jump table's address is read from its GOT slot or
  the slot's `RELATIVE` relocation; glibc's two-level `vfprintf` tables (a
  byte map, then `add; lwz n(rX)`) resolve.
- An unbounded table stops at a target past another function's start.
- `lr` and `ctr` travel through the tracker, so musl's `bl 1f; .long f -
  .; 1: mflr r6; lwz; add; mtctr r4; mr r4, r5; bctrl` calls `f`.
- Power10's eight-byte prefixed instructions decode, with `pla` addresses
  and `pld` GOT slots PC-relative (`ppc64le-power10-pie`).
- The data word after the 64-bit call to musl's `_start_c` reads as an
  invalid instruction: `__libc_start_main` reaches the second stage through
  an opaque register, so the walk cannot tell the call never returns.

## s390x

- GCC's jump tables (`clijh; risbgn; larl; lg; b 0(%rX,%rT)`) are read.

## SPARC

- GCC's jump tables (from the GOT pointer its PC thunk sets) and Sun
  Studio's (from `rd %pc`) are read; tables whose base is kept in a stack
  slot are not.

## SuperH

- `relocate` does not link calls in SuperH objects.
- PLT stubs are seeded from the header only.
- Code reached only through tables, or through pointers kept outside
  literal pools, is not found. A frame counts when GCC interleaves its setup
  with the saves (`mov.l r8, @-r15; mova; mov.l r9, @-r15`).
- Literal pools are not skipped by the sweep: data that decodes as
  `mov.l @(disp, pc)` would name "pools" inside real code.

## RISC-V

RV32 and RV64, with or without compressed instructions.

- Read: `jal`/`jalr` (calls through `ra` or `t0`, returns, `auipc; jalr` far
  calls), branches, `auipc; addi` and `lui; addi` addresses, `gp`-relative
  addresses (from `__global_pointer$`, or the `_start` code that sets `gp`),
  PLT stubs (`auipc t3; ld t3, n(t3); jalr t1, t3`), and jump tables bounded
  by `bltu`/`bgeu` against a constant, including GCC's RV64 zero-extended
  index (`slli 32; srli 30`) and Zba's `sh*add`, `slli.uw` and `zext.w`.
- PLT stubs are seeded from the section's fixed layout (a 32-byte header,
  16 bytes per import).
- Objects are linked, relaxation's branch relocations and `ADD32`/`SUB32`
  table entries included (`calls-riscv64.o`, `rv64-switch.o`).
- Dispatch through function pointers loaded from structs stays unresolved.

## LoongArch

LA64 only.

- Read: `b`, `bl`, the conditional branches, `jirl`, `pcaddu18i; jirl` far
  calls, the constants `pcaddi`, `pcalau12i`, `pcaddu12i`,
  `lu12i.w`/`ori`/`lu32i.d`/`lu52i.d` and `addi` build, PLT stubs, GOT calls
  through a slot, and jump tables bounded by `bltu`/`bgeu` (GCC's `alsl.d;
  ldptr.d; jr`, absolute; LLVM's `ldx.w; add.d; jr`, relative).
- The vector extensions decode as instructions that may write an integer
  register.
- Only a complete address, not a `pcalau12i` page, counts as a function
  pointer.
- Objects are linked (`B16`/`B21`/`B26`, `CALL36`, `PCALA`, GOT for
  imports, `32_PCREL`, `ADD`/`SUB`).

## m68k

- Every integer and FPU instruction's length decodes, including the
  68020's `bsr.l`, `extb.l`, bit fields and 32-bit `mul`/`div`.
- GCC's tables (`move.w (2, pc, d0.l*2), d0; jmp (2, pc, d0.w)`) are read,
  bounded in a register or in memory (`cmp.l 12(a3), d1`, then a reload of
  `12(a3)`).
- Addresses pushed (`pea main.l`) or stored (`move.l #f, ...`) are function
  pointers.
- Not done: PLT seeding, object relocation, and finding `main` (its
  arguments go on the stack).

## OpenRISC 1000

- `l.jal` to just past its delay slot (a PC read) or over a word of data is
  a jump, not a call.
- Integers built from `r0` (`l.ori rd, r0, n`) are not addresses; ones built
  like addresses (`l.movhi; l.ori`) are kept only where no explored function
  covers them.
- Tail calls through loaded function pointers stay unresolved.
- Not done: jump tables (none seen), PLT stubs, object relocations.

## MicroBlaze

- An `imm` prefix applies only to the instruction at the address after it;
  an immediate it did not widen is an integer.
- In a static link each GOT slot holds its target, which a call through it
  goes to.
- Not done: PLT stubs, object relocations, PIC jump tables (none seen).

## ARC

Little-endian ARCompact/ARC700 and ARCv2/HS.

- Entries into the `-mmillicode` epilogue (`__ld_r13_to_rN_ret`, jumped
  to) are functions of their own.
- `pcl`-relative addresses are held but are not function pointers (they
  point at data kept in `.text`); `st limm, [..]` stores one.
- ARCv2's `bi`/`bih` are implemented but untested on a sample.
- A bound set in the delay slot of a call to `__st_r13_to_rN`
  (`bl.d __st_r13_to_r16; cmp r0, 240`) is lost at the call, so such tables
  resolve no cases.
- Not done: the ARCompact PLT, object relocations.

## C-SKY

ABIv1 (CK510/CK610), little-endian, 16-bit instructions.

- The sweep steps over the literal pool words `lrw`/`jmpi`/`jsri` read, and
  no function inferred from a call or an address starts in one. Code that
  follows an unconditional end and pools, and starts with `subi r0, n` or
  `stm`, starts a function.
- PIC code's GOT base (`bsr 1f; 1: lrw r14, [offset]; addu r14, r15`) is
  learned once and held in `r14` at every block start. A pool word the next
  instruction adds to the PC is an offset, not an address. A far branch's
  `subi r0, 8; stw r15, (r0, 0); bsr 1f` is not a frame.
- An address only taken must be word-aligned to start a function.
- Uncalled leaf functions are missed.
- No jump tables are read (none seen; GCC compiles switches to compare
  chains on these samples).

## Xtensa

Little-endian, windowed ABI.

- A pass over each segment finds the `l32r` literal pool words, and the
  sweep steps over them as data. Every function opens with `entry`, so the
  sweep seeds each one it finds (word-aligned); a swept call whose target is
  not an `entry` is taken as a mis-decoded pool word and dropped.
- The `.plt` stub (`l32r a8, slot; l32i.n a8, a8, 0; jx a8`) is a double
  indirection that is not folded: imports are listed but their stubs are
  not linked to them.
- Switch tables through `addx4; l32i; jx` leave some jumps unresolved.

## Nios II and eBPF

- Nios II PLT stubs are followed to their imports (`bot-nios2-dynamic`).
- eBPF objects are decoded as whole programs; helper calls are calls to
  the kernel, not to code in the file (`ebpf-lirc-grundig`).
