//! What analysis needs from one instruction: its length, and where control
//! goes after it. Everything above this module is architecture-neutral.
//!
//! Each architecture's module has a `Decoder`, which holds the facts of
//! the image it decodes for (its byte order, word size, GOT) and what the
//! instructions decoded since the last reset left in registers, and
//! implements [`Decode`]. [`Decoder`] here picks one by the image's
//! architecture, alongside the [`Traits`] the analysis above consults.

pub(crate) mod arc;
pub(crate) mod arm;
pub(crate) mod arm64;
pub(crate) mod bpf;
pub(crate) mod csky;
pub(crate) mod loongarch;
pub(crate) mod m68k;
pub(crate) mod microblaze;
pub(crate) mod mips;
pub(crate) mod nios2;
pub(crate) mod openrisc;
pub(crate) mod ppc;
pub(crate) mod riscv;
pub(crate) mod s390x;
pub(crate) mod sparc;
pub(crate) mod superh;
pub(crate) mod x86;
pub(crate) mod xtensa;

use crate::{Arch, Binary, Segment};

/// One decoded instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Insn {
    /// Length in bytes; never zero, so a sweep always advances.
    pub(crate) len: u32,
    pub(crate) flow: Flow,
    /// What the instruction tells a later jump-table read.
    pub(crate) note: Note,
    /// Does nothing a stub cares about (`endbr64`, `nop`, `bti`): a stub may
    /// start with it and still be only a jump through a slot.
    pub(crate) pad: bool,
    /// A return, jump or trap that runs only when a condition holds (an Arm
    /// `bxne lr`, `ldrls pc, [...]`): control may also go on to the next
    /// instruction.
    pub(crate) falls: bool,
}

impl Insn {
    /// An instruction of `len` bytes that always does `flow`, and is no
    /// padding.
    pub(crate) const fn new(len: u32, flow: Flow) -> Self {
        Self {
            len,
            flow,
            note: Note::None,
            pad: false,
            falls: false,
        }
    }

    /// An instruction of `len` bytes that falls through, doing `note`.
    pub(crate) const fn note(len: u32, note: Note) -> Self {
        Self {
            note,
            ..Self::new(len, Flow::Next)
        }
    }

    /// The transfer `self` and the instruction in its delay slot, which
    /// runs before control arrives, as one instruction carrying the slot's
    /// note. A missing slot, one that does not decode, or one that is
    /// itself a transfer (undefined on every set with slots) makes the
    /// pair invalid: bytes that only look like a transfer.
    pub(crate) fn with_slot(self, slot: Option<Insn>) -> Self {
        match slot {
            Some(slot) if slot.flow == Flow::Next => Self {
                len: self.len.wrapping_add(slot.len),
                note: slot.note,
                ..self
            },
            _ => Self::new(self.len, Flow::Invalid),
        }
    }
}

/// Where control goes after an instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Flow {
    /// To the next instruction.
    Next,
    /// Unconditional direct jump.
    Jump(u64),
    /// Conditional direct branch: to the target, or to the next instruction.
    Branch(u64),
    /// Direct call.
    Call(u64),
    /// Call through the pointer stored at a fixed address.
    CallSlot(u64),
    /// Call through a register or computed address.
    CallIndirect,
    /// Call to the address in a register: a direct call, when the walk
    /// knows that address (PowerPC's `mtctr; bctrl`).
    CallRegister(u32),
    /// Jump through the pointer stored at a fixed address.
    JumpSlot(u64),
    /// Jump through the pointer stored at a computed address: a jump table,
    /// when the instructions before it say so.
    JumpMemory(Mem),
    /// Jump to the address in a register: a jump table, when the
    /// instructions before it say so.
    JumpRegister(u32),
    /// Jump to `base + (entry << shift)`, `entry` the unsigned `size`-byte
    /// value at `mem`: Thumb's `tbb` and `tbh`. A `size` of 0 makes the
    /// entry the case value itself, for a run of branch instructions that
    /// `add pc, pc, rN, lsl #2` indexes.
    JumpTable {
        mem: Mem,
        size: u8,
        base: u64,
        shift: u8,
    },
    /// Jump to the sum of two registers: a table's base and its entry.
    JumpAdd { base: u32, index: u32 },
    /// Jump somewhere that cannot be followed.
    JumpIndirect,
    /// Return.
    Return,
    /// Trap or halt.
    Stop,
    /// Bytes that do not decode as an instruction.
    Invalid,
}

impl Flow {
    /// Whether the flow is a call of any kind.
    pub(crate) const fn is_call(self) -> bool {
        matches!(
            self,
            Self::Call(_) | Self::CallSlot(_) | Self::CallIndirect | Self::CallRegister(_)
        )
    }

    /// A call, when `call`, else a jump, through register `reg`: to `target`
    /// when the register's value is known, else through the slot `loaded`
    /// names when the register was last loaded from it.
    pub(crate) fn through(
        reg: u32,
        target: Option<u64>,
        loaded: Option<(u32, u64)>,
        call: bool,
    ) -> Self {
        let slot = loaded
            .filter(|&(held, _)| held == reg)
            .map(|(_, slot)| slot);
        match (target, slot, call) {
            (Some(to), _, true) => Self::Call(to),
            (Some(to), _, false) => Self::Jump(to),
            (None, Some(slot), true) => Self::CallSlot(slot),
            (None, Some(slot), false) => Self::JumpSlot(slot),
            (None, None, true) => Self::CallRegister(reg),
            (None, None, false) => Self::JumpRegister(reg),
        }
    }
}

/// What an instruction does to registers, as far as finding a jump table
/// needs to know. Registers are numbered by the decoder from 0, below 64;
/// one number names a register at every width.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Note {
    /// Nothing worth knowing; writes no register a table depends on.
    None,
    /// `cmp reg, imm`: a table indexed by `reg` has `imm + 1` entries.
    Compare { reg: u32, imm: u64 },
    /// `reg = addr`, an address the instruction forms: PC-relative, an
    /// absolute address operand (on m68k, which has no high/low pairs, a
    /// long immediate), or the low half that completes a high/low pair.
    /// When it is code, the program may call it.
    Address { reg: u32, addr: u64 },
    /// `reg = value`, an integer that is no function's address by itself:
    /// an immediate, the high half of a pair, or the PC an instruction
    /// reads (PowerPC's `bcl 20, 31, $+4; mflr r30`). ARC's `pcl` sums are
    /// values too: they address constants and tables kept in the code,
    /// rarely functions. It holds even after
    /// a transfer: a call over data leaves the data's address in the link
    /// register.
    Value { reg: u32, value: u64 },
    /// `reg =` the `size`-byte value stored at `mem`, sign-extended when
    /// `signed`, where `mem` has no index and its base, if any, is a
    /// register the walk may know an address in: a GOT, TOC or
    /// literal-pool slot, whose value the walk reads from the image (a
    /// jump table's address, in 32-bit PowerPC PIC code: `lwz r3,
    /// n(r30)`). One the walk cannot place writes `reg` unknown.
    Fetch {
        reg: u32,
        mem: Mem,
        size: u8,
        signed: bool,
    },
    /// `reg =` the `size`-byte value at `mem`, sign-extended when `signed`:
    /// a table entry, which depends on the case value.
    Load {
        reg: u32,
        mem: Mem,
        size: u8,
        signed: bool,
    },
    /// `reg = src`.
    Copy { reg: u32, src: u32 },
    /// `reg = src + imm`.
    Offset { reg: u32, src: u32, imm: u64 },
    /// `reg = base + (extend(index) << shift)`.
    Add {
        reg: u32,
        base: u32,
        index: u32,
        shift: u8,
        extend: Extend,
    },
    /// Pushes a fixed address: `push imm`, or a call to the next
    /// instruction, which only pushes its own address.
    Push(u64),
    /// Pushes the value in `reg`.
    PushRegister(u32),
    /// `reg =` the value on top of the stack.
    Pop(u32),
    /// `reg = base - index`.
    Sub { reg: u32, base: u32, index: u32 },
    /// `reg` changes some other way.
    Write(u32),
    /// Each register `n` whose bit `1 << n` is set changes some other way: an
    /// instruction that writes several (registers numbered below 32).
    Clobber(u32),
}

impl Note {
    /// The registers the note says are written, as a mask. A compare
    /// writes none: it bounds the register it reads.
    pub(crate) fn writes(self) -> u64 {
        match self {
            Self::None | Self::Push(_) | Self::PushRegister(_) | Self::Compare { .. } => 0,
            Self::Clobber(regs) => u64::from(regs),
            Self::Address { reg, .. }
            | Self::Value { reg, .. }
            | Self::Fetch { reg, .. }
            | Self::Load { reg, .. }
            | Self::Copy { reg, .. }
            | Self::Offset { reg, .. }
            | Self::Add { reg, .. }
            | Self::Sub { reg, .. }
            | Self::Pop(reg)
            | Self::Write(reg) => {
                debug_assert!(reg < 64, "register {reg} out of range");
                1_u64.checked_shl(reg).unwrap_or(0)
            }
        }
    }
}

/// How an added register is widened before it is shifted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Extend {
    /// Used whole.
    None,
    /// Its low `n` bytes, zero-extended.
    Zero(u8),
    /// Its low `n` bytes, sign-extended.
    Sign(u8),
}

/// The memory operand `[base + index * scale + disp]`. A PC-relative operand
/// has neither register, and its absolute address as `disp`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Mem {
    pub(crate) base: Option<u32>,
    pub(crate) index: Option<u32>,
    pub(crate) scale: u8,
    pub(crate) disp: u64,
}

/// One architecture's decoder.
///
/// What earlier instructions left in registers follows control, by one
/// rule [`Decode::advance`] applies after each instruction: an instruction
/// that may fall through (or branch) keeps it, a call forgets what the
/// callee may change ([`Decode::call`]), and any other transfer forgets it
/// all, since only control from elsewhere reaches what follows. Callers
/// [`reset`](Decode::reset) wherever else control may arrive from
/// elsewhere, as at a block start.
pub(crate) trait Decode {
    /// The instruction at the start of `bytes`, mapped at `addr`. Bytes too
    /// few to hold one decode as [`Flow::Invalid`], still of nonzero length.
    fn decode(&mut self, bytes: &[u8], addr: u64) -> Insn;

    /// [`decode`](Decode::decode), then carry what the instruction leaves
    /// in registers on to the next one, by the rule above.
    fn advance(&mut self, bytes: &[u8], addr: u64) -> Insn {
        let insn = self.decode(bytes, addr);
        match insn.flow {
            Flow::Next | Flow::Branch(_) => {}
            _ if insn.falls => {}
            flow if flow.is_call() => self.call(),
            _ => self.reset(),
        }
        insn
    }

    /// Forget what earlier instructions left in registers.
    fn reset(&mut self);

    /// Forget what a call may change: the registers a callee need not
    /// preserve.
    fn call(&mut self);

    /// Whether `bytes` begin by setting up a frame, as only a function's
    /// first instructions do.
    fn starts_frame(&self, bytes: &[u8]) -> bool;

    /// The literal-pool word the instruction at the start of `bytes`, at
    /// `addr`, reads: data, not code, to a linear sweep.
    fn literal(&self, _bytes: &[u8], _addr: u64) -> Option<u64> {
        None
    }

    /// The entry of the function whose start the instruction at `addr`
    /// gives away.
    fn entry_of(&self, _bytes: &[u8], _addr: u64) -> Option<u64> {
        None
    }

    /// Where the function entered at `addr` starts, reading the code before
    /// it in `memory`.
    fn global_entry(&self, addr: u64, _memory: &Memory<'_>) -> u64 {
        addr
    }

    /// What a call at `call` to a PC thunk at the start of `bytes` leaves
    /// in a register, returning to `next`; `None` for any other callee.
    fn pc_thunk(&self, _bytes: &[u8], _call: u64, _next: u64) -> Option<Note> {
        None
    }

    /// The register that carries a call's `n`th argument (from zero);
    /// `None` when it goes on the stack, or the decoder does not track it.
    fn argument(&self, _n: usize) -> Option<u32> {
        None
    }
}

/// What the analysis above needs to know of an architecture, besides its
/// instructions.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Traits {
    /// Bytes in an address.
    width: u8,
    /// Instructions start at multiples of this, in the mode the sweep
    /// decodes.
    alignment: u64,
    /// What the sweep adds to an address to decode it in the mode most
    /// code is in: 1 for Thumb, whose addresses are odd.
    sweep_mode: u64,
    /// The alignment an address taken must have to be a function's.
    function_alignment: u64,
    /// A GOT slot of a function of the binary holds its address in the
    /// file, without a relocation to say so.
    slots_hold_targets: bool,
    /// A stub may compute its slot's address before jumping through it,
    /// rather than only pad.
    stub_arithmetic: bool,
    /// A fixed address loaded into a register is, when it points at code,
    /// a function whose address the program takes.
    notes_pointers: bool,
    /// Transfers have delay slots, which the decoder takes with them.
    delay_slots: bool,
    /// Compilers set the frame up after a function's first blocks.
    frames_late: bool,
    /// Every compiled function opens with a frame.
    calls_open_frames: bool,
    /// Literal-pool words sit before the instructions that read them.
    literals_behind: bool,
    /// The registers, as a mask, a callee leaves as they were, as far as a
    /// jump table after the call is concerned.
    call_preserved: u32,
}

impl Traits {
    /// A 32-bit set of 4-byte instructions with none of the quirks.
    const RISC: Self = Self {
        width: 4,
        alignment: 4,
        sweep_mode: 0,
        function_alignment: 1,
        slots_hold_targets: false,
        stub_arithmetic: true,
        notes_pointers: false,
        delay_slots: false,
        frames_late: false,
        calls_open_frames: false,
        literals_behind: false,
        call_preserved: 0,
    };

    /// The traits of `arch`, decoded mostly as Thumb when `thumb`.
    const fn of(arch: Arch, thumb: bool) -> Self {
        let width = arch.address_width();
        let risc = Self {
            width,
            ..Self::RISC
        };
        match arch {
            Arch::X86 | Arch::X86_64 => Self {
                alignment: 1,
                stub_arithmetic: false,
                ..risc
            },
            Arch::Arm64 | Arch::PowerPc64 | Arch::PowerPc64El => risc,
            Arch::LoongArch64 | Arch::Nios2 | Arch::PowerPc | Arch::PowerPcEl => Self {
                notes_pointers: true,
                ..risc
            },
            Arch::Arm if thumb => Self {
                alignment: 2,
                sweep_mode: 1,
                ..risc
            },
            Arch::Arm => risc,
            Arch::Mips
            | Arch::MipsEl
            | Arch::Mips64
            | Arch::Mips64El
            | Arch::MipsR6
            | Arch::MipsR6El
            | Arch::Mips64R6
            | Arch::Mips64R6El => Self {
                // MIPS GOTs hold their functions' addresses.
                slots_hold_targets: true,
                delay_slots: true,
                // GCC shrink-wraps `addiu $sp` past an early return.
                frames_late: true,
                ..risc
            },
            Arch::S390x | Arch::RiscV32 | Arch::RiscV64 => Self {
                alignment: 2,
                ..risc
            },
            Arch::Sparc | Arch::Sparc64 => Self {
                delay_slots: true,
                // GCC shrink-wraps `save` past an early return.
                frames_late: true,
                call_preserved: sparc::CALL_PRESERVED,
                ..risc
            },
            // Literal-pool loads hold data, callees and callbacks.
            Arch::SuperH => Self {
                alignment: 2,
                notes_pointers: true,
                delay_slots: true,
                ..risc
            },
            Arch::M68k => Self {
                alignment: 2,
                notes_pointers: true,
                ..risc
            },
            Arch::OpenRisc => Self {
                notes_pointers: true,
                delay_slots: true,
                ..risc
            },
            // Statically linked MicroBlaze GOTs hold their functions'
            // addresses, which PIC code calls through.
            Arch::MicroBlaze | Arch::MicroBlazeEl => Self {
                slots_hold_targets: true,
                notes_pointers: true,
                delay_slots: true,
                ..risc
            },
            Arch::Arc | Arch::ArcV2 => Self {
                alignment: 2,
                notes_pointers: true,
                delay_slots: true,
                ..risc
            },
            // GCC aligns functions to words, and a halfword-aligned
            // integer in a literal pool is no function.
            Arch::CSky | Arch::MCore => Self {
                alignment: 2,
                function_alignment: 4,
                notes_pointers: true,
                ..risc
            },
            // The windowed ABI starts each function with `entry`, and
            // `l32r` reads pools before it.
            Arch::Xtensa => Self {
                alignment: 1,
                function_alignment: 4,
                notes_pointers: true,
                calls_open_frames: true,
                literals_behind: true,
                ..risc
            },
            Arch::Bpf => Self {
                alignment: 8,
                ..risc
            },
        }
    }
}

/// An instruction decoder for one image's architecture.
#[derive(Clone)]
pub(crate) struct Decoder {
    isa: Isa,
    traits: Traits,
}

/// Each architecture's decoder. All are boxed, so that the enum is one
/// pointer whatever an architecture keeps in registers.
#[derive(Clone)]
enum Isa {
    X86(Box<x86::Decoder>),
    Arm64(Box<arm64::Decoder>),
    Arm(Box<arm::Decoder>),
    Mips(Box<mips::Decoder>),
    S390x(Box<s390x::Decoder>),
    Sparc(Box<sparc::Decoder>),
    SuperH(Box<superh::Decoder>),
    PowerPc(Box<ppc::Decoder>),
    RiscV(Box<riscv::Decoder>),
    LoongArch(Box<loongarch::Decoder>),
    M68k(Box<m68k::Decoder>),
    OpenRisc(Box<openrisc::Decoder>),
    MicroBlaze(Box<microblaze::Decoder>),
    Arc(Box<arc::Decoder>),
    CSky(Box<csky::Decoder>),
    Xtensa(Box<xtensa::Decoder>),
    Bpf(Box<bpf::Decoder>),
    Nios2(Box<nios2::Decoder>),
}

/// `$body`, with `$d` bound to the architecture's decoder.
macro_rules! each {
    ($isa:expr, $d:ident => $body:expr) => {
        match $isa {
            Isa::X86($d) => $body,
            Isa::Arm64($d) => $body,
            Isa::Arm($d) => $body,
            Isa::Mips($d) => $body,
            Isa::S390x($d) => $body,
            Isa::Sparc($d) => $body,
            Isa::SuperH($d) => $body,
            Isa::PowerPc($d) => $body,
            Isa::RiscV($d) => $body,
            Isa::LoongArch($d) => $body,
            Isa::M68k($d) => $body,
            Isa::OpenRisc($d) => $body,
            Isa::MicroBlaze($d) => $body,
            Isa::Arc($d) => $body,
            Isa::CSky($d) => $body,
            Isa::Xtensa($d) => $body,
            Isa::Bpf($d) => $body,
            Isa::Nios2($d) => $body,
        }
    };
}

impl Decoder {
    pub(crate) fn new(image: &Binary<'_>, arch: Arch) -> Self {
        // The mode most known starts are in: Thumb addresses are odd.
        let odd = image.seeds.iter().filter(|seed| seed.addr & 1 != 0).count();
        let thumb = arch == Arch::Arm && odd.saturating_mul(2) > image.seeds.len();
        let wide = arch.address_width() == 8;
        let big = arch.big_endian();
        let isa = match arch {
            Arch::X86 => Isa::X86(Box::new(x86::Decoder::new(32, image.got))),
            Arch::X86_64 => Isa::X86(Box::new(x86::Decoder::new(64, None))),
            Arch::Arm64 => Isa::Arm64(Box::default()),
            Arch::Arm => Isa::Arm(Box::new(arm::Decoder::new(thumb))),
            Arch::Mips
            | Arch::MipsEl
            | Arch::Mips64
            | Arch::Mips64El
            | Arch::MipsR6
            | Arch::MipsR6El
            | Arch::Mips64R6
            | Arch::Mips64R6El => Isa::Mips(Box::new(mips::Decoder::new(image, arch))),
            Arch::S390x => Isa::S390x(Box::default()),
            Arch::Sparc | Arch::Sparc64 => Isa::Sparc(Box::new(sparc::Decoder::new(wide))),
            Arch::SuperH => Isa::SuperH(Box::default()),
            Arch::PowerPc | Arch::PowerPcEl | Arch::PowerPc64 | Arch::PowerPc64El => {
                Isa::PowerPc(Box::new(ppc::Decoder::new(big, wide, image.got)))
            }
            Arch::RiscV32 | Arch::RiscV64 => {
                Isa::RiscV(Box::new(riscv::Decoder::new(riscv::Config {
                    wide,
                    gp: image.got,
                })))
            }
            Arch::LoongArch64 => Isa::LoongArch(Box::default()),
            Arch::M68k => Isa::M68k(Box::default()),
            Arch::OpenRisc => Isa::OpenRisc(Box::default()),
            Arch::MicroBlaze | Arch::MicroBlazeEl => {
                Isa::MicroBlaze(Box::new(microblaze::Decoder::new(big)))
            }
            Arch::Arc | Arch::ArcV2 => Isa::Arc(Box::new(arc::Decoder::new(arch == Arch::ArcV2))),
            Arch::CSky | Arch::MCore => Isa::CSky(Box::default()),
            Arch::Xtensa => Isa::Xtensa(Box::default()),
            Arch::Bpf => Isa::Bpf(Box::default()),
            Arch::Nios2 => Isa::Nios2(Box::default()),
        };
        Self {
            isa,
            traits: Traits::of(arch, thumb),
        }
    }

    /// Forget what earlier instructions left in registers. Called wherever
    /// control may arrive from elsewhere.
    pub(crate) fn reset(&mut self) {
        each!(&mut self.isa, d => d.reset());
    }

    /// Decode the instruction at the start of `bytes`, mapped at `addr`,
    /// and carry what it leaves in registers on as [`Decode`] says.
    ///
    /// No instruction is empty: every walk steps on by lengths, and one of
    /// zero would hold it at the same address for good. A decoder that
    /// reports one has its bytes taken as invalid, a unit of alignment long.
    pub(crate) fn decode(&mut self, bytes: &[u8], addr: u64) -> Insn {
        let insn = each!(&mut self.isa, d => d.advance(bytes, addr));
        if insn.len == 0 {
            let unit = u32::try_from(self.alignment()).unwrap_or(1).max(1);
            return Insn::new(unit, Flow::Invalid);
        }
        insn
    }

    /// Whether a GOT slot of a function of the binary holds its address in
    /// the file: MIPS GOTs do, without relocations to say so, and so do
    /// statically linked MicroBlaze ones (PIC code calls through them).
    pub(crate) const fn slots_hold_targets(&self) -> bool {
        self.traits.slots_hold_targets
    }

    /// Bytes in an address.
    pub(crate) const fn address_width(&self) -> u8 {
        self.traits.width
    }

    /// Instructions start at multiples of this, in the mode the sweep
    /// decodes.
    pub(crate) const fn alignment(&self) -> u64 {
        self.traits.alignment
    }

    /// The alignment an address taken must have to be a function's: C-SKY's
    /// GCC aligns functions to words, and a halfword-aligned integer in its
    /// literal pools is no function. Elsewhere, any (a Thumb pointer is odd).
    pub(crate) const fn function_alignment(&self) -> u64 {
        self.traits.function_alignment
    }

    /// What the sweep adds to an address to decode it in the mode most code
    /// is in: 1 for Thumb, whose addresses are odd.
    pub(crate) const fn sweep_mode(&self) -> u64 {
        self.traits.sweep_mode
    }

    /// Whether a stub may compute its slot's address before jumping
    /// through it, as on the fixed-width RISC sets, rather than only pad.
    pub(crate) const fn stub_arithmetic(&self) -> bool {
        self.traits.stub_arithmetic
    }

    /// What a call at `call` to a PC thunk at the start of `bytes` leaves in
    /// a register, returning to `next`; `None` for any other callee. On
    /// i386 the register holds `next`; SPARC's thunk adds the call's own
    /// address to it.
    pub(crate) fn pc_thunk(&self, bytes: &[u8], call: u64, next: u64) -> Option<Note> {
        each!(&self.isa, d => d.pc_thunk(bytes, call, next))
    }

    /// The registers, as a mask, a callee leaves as they were, as far as
    /// a jump table after the call is concerned.
    pub(crate) const fn call_preserved(&self) -> u32 {
        self.traits.call_preserved
    }

    /// Whether a fixed address an instruction loads into a register is, when
    /// it points at code, a function whose address the program takes: true
    /// of SuperH's literal-pool loads, which hold data, callees and
    /// callbacks (other sets also note addresses inside the function).
    pub(crate) const fn notes_pointers(&self) -> bool {
        self.traits.notes_pointers
    }

    /// Whether transfers have delay slots, which the decoder takes with
    /// them: a call's or jump's note is its slot's, which applies before
    /// the target.
    pub(crate) const fn delay_slots(&self) -> bool {
        self.traits.delay_slots
    }

    /// The register that carries a call's `n`th argument (from zero) under
    /// the System V and A64 conventions; `None` when it goes on the stack,
    /// or the decoder does not track the registers arguments travel in.
    pub(crate) fn argument(&self, n: usize) -> Option<u32> {
        each!(&self.isa, d => d.argument(n))
    }

    /// Whether `bytes` begin by setting up a frame pointer, as only a
    /// function's first instructions do.
    pub(crate) fn starts_frame(&self, bytes: &[u8]) -> bool {
        each!(&self.isa, d => d.starts_frame(bytes))
    }

    /// The literal-pool word the instruction at the start of `bytes`, at
    /// `addr`, reads, ahead of it: data, not code, to a linear sweep (C-SKY
    /// keeps its pools between functions, after the last jump).
    pub(crate) fn literal(&self, bytes: &[u8], addr: u64) -> Option<u64> {
        each!(&self.isa, d => d.literal(bytes, addr))
    }

    /// Whether compilers set the frame up after a function's first blocks
    /// (GCC shrink-wraps SPARC's `save` and MIPS's `addiu $sp` past an
    /// early return), so a jump to a frame setup is a branch within the
    /// function, not a tail call.
    pub(crate) const fn frames_late(&self) -> bool {
        self.traits.frames_late
    }

    /// Whether every compiled function opens with a frame, so a call
    /// target that does not is a mis-decoded pool word, not a function
    /// (Xtensa's windowed ABI starts each function with `entry`).
    pub(crate) const fn calls_open_frames(&self) -> bool {
        self.traits.calls_open_frames
    }

    /// Whether literal-pool words sit *before* the instruction that reads
    /// them (Xtensa's `l32r`), so a sweep must find them in a pass of its
    /// own rather than skip them as it reaches them (C-SKY's lie ahead).
    pub(crate) const fn literals_behind(&self) -> bool {
        self.traits.literals_behind
    }

    /// The entry of the function whose start the instruction at `addr`
    /// gives away: `addr` itself for code only a function's first
    /// instructions can be (64-bit ELFv2's global entry, ARC's millicode
    /// epilogue), or on MIPS the entry a `$gp` setup computes from `$t9`,
    /// a few instructions before it in n64 code.
    pub(crate) fn entry_of(&self, bytes: &[u8], addr: u64) -> Option<u64> {
        each!(&self.isa, d => d.entry_of(bytes, addr))
    }

    /// Where the function entered at `addr` starts: 64-bit ELFv2 code
    /// enters a function eight bytes in from within its module, past the
    /// instructions that set the TOC pointer.
    pub(crate) fn global_entry(&self, addr: u64, memory: &Memory<'_>) -> u64 {
        each!(&self.isa, d => d.global_entry(addr, memory))
    }
}

/// The 16-bit word at `bytes[at..]`, most significant byte first when
/// `big`.
pub(crate) fn u16_at(bytes: &[u8], at: usize, big: bool) -> Option<u16> {
    let word = bytes.get(at..at.checked_add(2)?)?.try_into().ok()?;
    Some(if big {
        u16::from_be_bytes(word)
    } else {
        u16::from_le_bytes(word)
    })
}

/// The 32-bit word at `bytes[at..]`, most significant byte first when
/// `big`.
pub(crate) fn u32_at(bytes: &[u8], at: usize, big: bool) -> Option<u32> {
    let word = bytes.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(if big {
        u32::from_be_bytes(word)
    } else {
        u32::from_le_bytes(word)
    })
}

/// The unsigned integer stored in `bytes`, at most eight of them, most
/// significant byte first when `big`.
pub(crate) fn uint(bytes: &[u8], big: bool) -> Option<u64> {
    let word = |value: u64, &byte: &u8| value << 8 | u64::from(byte);
    (bytes.len() <= 8).then(|| {
        if big {
            bytes.iter().fold(0, word)
        } else {
            bytes.iter().rev().fold(0, word)
        }
    })
}

/// The low `bits` bits of `value`, sign-extended; `bits` is 1 to 64.
pub(crate) fn sext(value: impl Into<u64>, bits: u32) -> i64 {
    debug_assert!((1..=64).contains(&bits), "{bits}-bit field");
    let shift = 64_u32.saturating_sub(bits);
    (value.into() << shift).cast_signed() >> shift
}

/// The target of a branch: `base` plus the signed `bits`-bit `field`
/// times `scale`, wrapping.
pub(crate) fn relative(base: u64, field: impl Into<u64>, bits: u32, scale: i64) -> u64 {
    base.wrapping_add_signed(sext(field, bits).wrapping_mul(scale))
}

/// What an instruction leaves for the ones right after it, until one
/// overwrites a register it names: the steps by which a load/store
/// architecture builds a jump table's address over several instructions.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Pending {
    /// A register holding another shifted left, and by how much.
    pub(crate) scaled: Option<(u32, u8)>,
    /// A register holding a base plus a scaled register, which a load then
    /// reads through.
    pub(crate) indexed: Option<Indexed>,
    /// The last register loaded from a fixed address, and that address.
    pub(crate) loaded: Option<(u32, u64)>,
}

/// `sum = base + (index << shift)`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Indexed {
    pub(crate) sum: u32,
    pub(crate) base: u32,
    pub(crate) index: u32,
    pub(crate) shift: u8,
}

/// `reg` as a register mask.
pub(crate) fn bit(reg: u32) -> u64 {
    1_u64.checked_shl(reg).unwrap_or(0)
}

impl Pending {
    /// The registers whose earlier facts end at the instruction that noted
    /// `note` and left `self`: those it writes, and the sum it made.
    pub(crate) fn written(&self, note: Note) -> u64 {
        note.writes() | self.indexed.map_or(0, |indexed| bit(indexed.sum))
    }

    /// Carry each fact `before` the instruction that left `self` into it,
    /// unless the instruction made a new one of its kind or overwrote, in
    /// `written`, a register the fact names.
    pub(crate) fn keep(&mut self, before: Self, written: u64) {
        let kept = |regs: u64| written & regs == 0;
        self.scaled = self
            .scaled
            .or(before.scaled.filter(|&(reg, _)| kept(bit(reg))));
        self.indexed = self.indexed.or(before
            .indexed
            .filter(|i| kept(bit(i.sum) | bit(i.base) | bit(i.index))));
        self.loaded = self
            .loaded
            .or(before.loaded.filter(|&(reg, _)| kept(bit(reg))));
    }
}

/// What a decoder knows of the values in `N` registers.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Regs<T, const N: usize>([Option<T>; N]);

impl<T: Copy, const N: usize> Default for Regs<T, N> {
    fn default() -> Self {
        Self([None; N])
    }
}

impl<T: Copy, const N: usize> Regs<T, N> {
    /// What `reg` holds, if known.
    pub(crate) fn get(&self, reg: u32) -> Option<T> {
        self.0.get(usize::try_from(reg).ok()?).copied().flatten()
    }

    /// Record what `reg` holds; `None` forgets it.
    pub(crate) fn set(&mut self, reg: u32, value: Option<T>) {
        if let Some(slot) = usize::try_from(reg)
            .ok()
            .and_then(|reg| self.0.get_mut(reg))
        {
            *slot = value;
        }
    }

    /// Forget each register whose bit is set in `mask`.
    pub(crate) fn forget(&mut self, mask: u64) {
        for (reg, slot) in self.0.iter_mut().enumerate().take(64) {
            if mask >> reg & 1 != 0 {
                *slot = None;
            }
        }
    }
}

/// The mapped segments of an image, searchable by address.
pub(crate) struct Memory<'a> {
    /// Sorted by address.
    segments: Vec<Span<'a>>,
    /// Which segment holds each address: sorted, disjoint runs, each from
    /// its address to the next run's, of `segments[index]` or of nothing.
    views: Vec<(u64, Option<usize>)>,
    /// Words are stored most significant byte first.
    big: bool,
    /// Cleared from a code address before it is looked up: bit 0, which
    /// marks Thumb code, on 32-bit Arm.
    code_mask: u64,
}

/// One segment's bytes, borrowed from the image.
#[derive(Clone, Copy)]
pub(crate) struct Span<'a> {
    pub(crate) addr: u64,
    pub(crate) bytes: &'a [u8],
    pub(crate) executable: bool,
}

impl<'a> Memory<'a> {
    pub(crate) fn new(segments: &'a [Segment<'_>]) -> Self {
        let mut segments: Vec<Span<'a>> = segments
            .iter()
            .filter(|segment| !segment.bytes.is_empty())
            .map(|segment| Span {
                addr: segment.addr,
                bytes: &segment.bytes,
                executable: segment.executable,
            })
            .collect();
        segments.sort_by_key(|segment| segment.addr);
        let views = views(&segments);
        Self {
            segments,
            views,
            big: false,
            code_mask: !0,
        }
    }

    /// The segments, read as `arch` reads them: in its byte order, and on
    /// 32-bit Arm with a Thumb address's bit 0 cleared to find its code.
    pub(crate) fn for_arch(segments: &'a [Segment<'_>], arch: Arch) -> Self {
        Self {
            big: arch.big_endian(),
            code_mask: if arch == Arch::Arm { !1 } else { !0 },
            ..Self::new(segments)
        }
    }

    /// The bytes from `addr` to the end of its segment, and whether they are
    /// code.
    pub(crate) fn at(&self, addr: u64) -> Option<(&'a [u8], bool)> {
        let view = self
            .views
            .partition_point(|&(start, _)| start <= addr)
            .checked_sub(1)?;
        let (_, index) = *self.views.get(view)?;
        let segment = self.segments.get(index?)?;
        let offset = usize::try_from(addr.checked_sub(segment.addr)?).ok()?;
        let bytes = segment
            .bytes
            .get(offset..)
            .filter(|bytes| !bytes.is_empty())?;
        Some((bytes, segment.executable))
    }

    /// The mapped bytes, each address once: disjoint runs in address
    /// order, each from the segment [`Memory::at`] reads it from. Walks
    /// over them cost the bytes mapped, however many segments overlap.
    pub(crate) fn spans(&self) -> impl Iterator<Item = Span<'a>> {
        self.spans_from(0)
    }

    /// The spans from the one in `self.views[first]` on.
    fn spans_from(&self, first: usize) -> impl Iterator<Item = Span<'a>> {
        let views = self.views.get(first..).unwrap_or_default();
        let nexts = views.iter().skip(1).map(|&(at, _)| Some(at)).chain([None]);
        let segments = &self.segments;
        views
            .iter()
            .zip(nexts)
            .filter_map(move |(&(at, index), next)| {
                let segment = segments.get(index?)?;
                let offset = usize::try_from(at.checked_sub(segment.addr)?).ok()?;
                let bytes = segment.bytes.get(offset..)?;
                // A view runs to the next one's start, within its segment.
                let len = next
                    .and_then(|next| usize::try_from(next.checked_sub(at)?).ok())
                    .unwrap_or(usize::MAX);
                Some(Span {
                    addr: at,
                    bytes: bytes.get(..len.min(bytes.len()))?,
                    executable: segment.executable,
                })
            })
    }

    /// The mapped bytes from `start` up to `end`, as [`Memory::spans`]
    /// gives them.
    pub(crate) fn within(&self, start: u64, end: u64) -> impl Iterator<Item = (u64, &'a [u8])> {
        let first = self
            .views
            .partition_point(|&(at, _)| at <= start)
            .saturating_sub(1);
        self.spans_from(first)
            .take_while(move |span| span.addr < end)
            .filter_map(move |span| {
                let from = span.addr.max(start);
                let skip = usize::try_from(from.checked_sub(span.addr)?).ok()?;
                let len = usize::try_from(end.checked_sub(from)?).unwrap_or(usize::MAX);
                let bytes = span.bytes.get(skip..)?;
                let bytes = bytes.get(..len.min(bytes.len()))?;
                (!bytes.is_empty()).then_some((from, bytes))
            })
    }

    /// The code from `addr` to the end of its segment, when `addr` is in
    /// executable code.
    pub(crate) fn code(&self, addr: u64) -> Option<&'a [u8]> {
        self.at(addr & self.code_mask)
            .and_then(|(bytes, executable)| executable.then_some(bytes))
    }

    pub(crate) fn is_code(&self, addr: u64) -> bool {
        self.code(addr).is_some()
    }

    /// The unsigned integer of `size` bytes, at most eight, stored at
    /// `addr` in the image's byte order.
    pub(crate) fn read(&self, addr: u64, size: u8) -> Option<u64> {
        let (bytes, _) = self.at(addr)?;
        uint(bytes.get(..usize::from(size))?, self.big)
    }

    /// Whether words are stored most significant byte first.
    pub(crate) fn big_endian(&self) -> bool {
        self.big
    }
}

/// Which of `segments` (sorted by address) holds each address, as
/// [`Memory::views`] records it. Where segments overlap, as a malformed
/// header can make them, the one that starts last holds the address, of
/// those listed last when several start together: resolved once here, so a
/// lookup costs one binary search however many segments a file stacks.
fn views(segments: &[Span<'_>]) -> Vec<(u64, Option<usize>)> {
    // Where each segment ends; one that reaches the top of the address
    // space never does.
    let mut ends: Vec<(u64, usize)> = segments
        .iter()
        .enumerate()
        .filter_map(|(i, segment)| {
            let len = u64::try_from(segment.bytes.len()).ok()?;
            Some((segment.addr.checked_add(len)?, i))
        })
        .collect();
    ends.sort_unstable();
    let mut ends = ends.into_iter().peekable();
    let mut starts = segments
        .iter()
        .enumerate()
        .map(|(i, segment)| (segment.addr, i))
        .peekable();
    let mut open = std::collections::BTreeSet::new();
    let mut views: Vec<(u64, Option<usize>)> = Vec::new();
    loop {
        let at = match (starts.peek(), ends.peek()) {
            (Some(&(start, _)), Some(&(end, _))) => start.min(end),
            (Some(&(start, _)), None) => start,
            (None, Some(&(end, _))) => end,
            (None, None) => break,
        };
        while let Some((_, i)) = ends.next_if(|&(end, _)| end == at) {
            open.remove(&i);
        }
        while let Some((_, i)) = starts.next_if(|&(start, _)| start == at) {
            open.insert(i);
        }
        let top = open.last().copied();
        if views.last().map(|&(_, index)| index) != Some(top) {
            views.push((at, top));
        }
    }
    views
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Format, Seed};
    use std::borrow::Cow;

    /// A fact lasts until an instruction overwrites a register it names or
    /// makes a new one of its kind; a compare overwrites nothing.
    #[test]
    fn pending_facts_last_until_overwritten() {
        let before = Pending {
            scaled: Some((5, 2)),
            indexed: Some(Indexed {
                sum: 6,
                base: 7,
                index: 5,
                shift: 2,
            }),
            loaded: Some((8, 0x1000)),
        };
        let compare = Note::Compare { reg: 5, imm: 3 };
        let mut after = Pending::default();
        after.keep(before, after.written(compare));
        assert_eq!(after.scaled, Some((5, 2)));
        assert!(after.indexed.is_some());
        assert_eq!(after.loaded, Some((8, 0x1000)));

        // Writing r7 ends the sum built on it, not the scaled copy.
        let mut after = Pending::default();
        after.keep(before, after.written(Note::Write(7)));
        assert_eq!(after.scaled, Some((5, 2)));
        assert!(after.indexed.is_none());

        // A new load replaces the old one.
        let mut after = Pending {
            loaded: Some((9, 0x2000)),
            ..Pending::default()
        };
        after.keep(before, after.written(Note::None));
        assert_eq!(after.loaded, Some((9, 0x2000)));
    }

    fn segment(addr: u64, bytes: &[u8], executable: bool) -> Segment<'_> {
        Segment {
            addr,
            bytes: Cow::Borrowed(bytes),
            executable,
        }
    }

    #[test]
    fn overlapping_segments_fall_back_to_one_that_holds_the_address() {
        let (low, high) = ([1_u8; 0x100], [2_u8; 0x10]);
        let segments = [segment(0x1000, &low, true), segment(0x1080, &high, false)];
        let memory = Memory::new(&segments);
        // Inside the later segment, which starts nearer.
        assert_eq!(
            memory.at(0x1088).map(|(b, x)| (b[0], b.len(), x)),
            Some((2, 8, false))
        );
        // Past its end, but inside the earlier one, which overlaps it.
        assert_eq!(
            memory.at(0x1090).map(|(b, x)| (b[0], b.len(), x)),
            Some((1, 0x70, true))
        );
        assert!(memory.at(0x1100).is_none());
        assert!(memory.at(0xfff).is_none());
        assert!(memory.is_code(0x10ff));
        assert!(!memory.is_code(0x1080));
    }

    #[test]
    fn nested_segments_resume_the_one_below_where_they_end() {
        let (outer, middle, inner) = ([1_u8; 0x100], [2_u8; 0x40], [3_u8; 0x10]);
        let segments = [
            segment(0x1000, &outer, true),
            segment(0x1020, &middle, false),
            segment(0x1030, &inner, true),
            // Starts with the outer one but is listed later: it shows.
            segment(0x1000, &[4_u8; 8], false),
        ];
        let memory = Memory::new(&segments);
        let at = |addr| memory.at(addr).map(|(b, x)| (b[0], b.len(), x));
        assert_eq!(at(0x1000), Some((4, 8, false)));
        assert_eq!(at(0x1008), Some((1, 0xf8, true)));
        assert_eq!(at(0x1020), Some((2, 0x40, false)));
        assert_eq!(at(0x1035), Some((3, 0xb, true)));
        assert_eq!(at(0x1040), Some((2, 0x20, false)));
        assert_eq!(at(0x1060), Some((1, 0xa0, true)));
        assert_eq!(at(0x1100), None);

        // Each address once, from the segment that shows there.
        let runs: Vec<(u64, u8, usize)> = memory
            .within(0x1004, 0x1048)
            .map(|(addr, bytes)| (addr, bytes[0], bytes.len()))
            .collect();
        assert_eq!(
            runs,
            [
                (0x1004, 4, 4),
                (0x1008, 1, 0x18),
                (0x1020, 2, 0x10),
                (0x1030, 3, 0x10),
                (0x1040, 2, 8),
            ]
        );
    }

    #[test]
    fn a_segment_reaching_the_top_of_the_address_space_holds_it() {
        let bytes = [5_u8; 0x10];
        let segments = [segment(u64::MAX - 0xf, &bytes, false)];
        let memory = Memory::new(&segments);
        assert_eq!(memory.at(u64::MAX).map(|(b, _)| b.len()), Some(1));
        assert_eq!(memory.within(u64::MAX - 1, u64::MAX).count(), 1);
    }

    /// A header can stack a segment per section: a lookup that misses all
    /// of them, or falls through all of them to one below, stays cheap.
    #[test]
    fn stacked_segments_cost_one_search() {
        let (base, tiny) = ([1_u8; 0x10_0000], [2_u8; 1]);
        let mut segments = vec![segment(0, &base, true)];
        segments.extend((1..=0x1_0000).map(|i| segment(i * 8, &tiny, false)));
        let memory = Memory::new(&segments);
        for i in 0..0x1_0000_u64 {
            assert!(memory.is_code(0x8_0001 + i));
            assert!(memory.at(0x20_0000 + i).is_none());
        }
        assert_eq!(
            memory
                .within(0, 0x10_0000)
                .map(|(_, b)| b.len())
                .sum::<usize>(),
            0x10_0000
        );
    }

    #[test]
    fn reads_in_the_byte_order_of_the_arch() {
        let bytes = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];
        let segments = [segment(0x2000, &bytes, false)];
        let little = Memory::for_arch(&segments, Arch::X86_64);
        let big = Memory::for_arch(&segments, Arch::Mips);
        assert_eq!(little.read(0x2000, 4), Some(0x4433_2211));
        assert_eq!(big.read(0x2000, 4), Some(0x1122_3344));
        assert_eq!(big.read(0x2001, 8), Some(0x2233_4455_6677_8899));
        assert_eq!(little.read(0x2000, 0), Some(0));
        // Too wide, or running off the segment's end.
        assert_eq!(little.read(0x2000, 9), None);
        assert_eq!(little.read(0x2006, 4), None);
        assert_eq!(little.read(0x1fff, 1), None);
    }

    #[test]
    fn notes_name_the_registers_they_write() {
        assert_eq!(Note::None.writes(), 0);
        assert_eq!(Note::Push(4).writes(), 0);
        assert_eq!(Note::Clobber(0b1010).writes(), 0b1010);
        assert_eq!(Note::Write(15).writes(), 1 << 15);
        assert_eq!(Note::Copy { reg: 63, src: 0 }.writes(), 1 << 63);
        assert_eq!(Note::Value { reg: 2, value: 7 }.writes(), 4);
    }

    #[test]
    fn helpers_read_words_and_extend_signs() {
        let bytes = [0x12, 0x34, 0x56, 0x78, 0x9a];
        assert_eq!(u16_at(&bytes, 1, true), Some(0x3456));
        assert_eq!(u16_at(&bytes, 1, false), Some(0x5634));
        assert_eq!(u32_at(&bytes, 1, true), Some(0x3456_789a));
        assert_eq!(u32_at(&bytes, 2, true), None);
        assert_eq!(u32_at(&bytes, usize::MAX, true), None);
        assert_eq!(sext(0x80_u32, 8), -128);
        assert_eq!(sext(0x7f_u32, 8), 127);
        assert_eq!(sext(u64::MAX, 64), -1);
        assert_eq!(sext(0x1_u32, 1), -1);
        assert_eq!(relative(0x1000, 0xfff_u32, 12, 2), 0xffe);
        assert_eq!(relative(0, 1_u32, 12, 4), 4);
    }

    #[test]
    fn regs_forget_by_mask() {
        let mut regs = Regs::<u64, 4>::default();
        regs.set(1, Some(10));
        regs.set(3, Some(30));
        regs.set(9, Some(90));
        assert_eq!(regs.get(9), None);
        regs.forget(0b1000);
        assert_eq!((regs.get(1), regs.get(3)), (Some(10), None));
    }

    /// Every architecture, in every configuration its decoder has.
    const ARCHES: [Arch; 34] = [
        Arch::X86,
        Arch::X86_64,
        Arch::Arm64,
        Arch::Arm,
        Arch::Mips,
        Arch::MipsEl,
        Arch::Mips64,
        Arch::Mips64El,
        Arch::MipsR6,
        Arch::MipsR6El,
        Arch::Mips64R6,
        Arch::Mips64R6El,
        Arch::S390x,
        Arch::Sparc,
        Arch::Sparc64,
        Arch::SuperH,
        Arch::PowerPc,
        Arch::PowerPcEl,
        Arch::PowerPc64,
        Arch::PowerPc64El,
        Arch::RiscV32,
        Arch::RiscV64,
        Arch::LoongArch64,
        Arch::M68k,
        Arch::OpenRisc,
        Arch::MicroBlaze,
        Arch::MicroBlazeEl,
        Arch::Arc,
        Arch::ArcV2,
        Arch::CSky,
        Arch::MCore,
        Arch::Xtensa,
        Arch::Bpf,
        Arch::Nios2,
    ];

    /// Every decoder takes any bytes, at any address: each prefix of up to
    /// eight bytes, at each offset of a pseudo-random buffer, decodes
    /// without a panic to an instruction of nonzero length.
    #[test]
    fn decoders_take_any_bytes() {
        let mut buffer = vec![0_u8; 4096];
        let mut x = 0x9e37_79b9_7f4a_7c15_u64;
        for byte in &mut buffer {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *byte = x.to_le_bytes()[0];
        }
        let base = 0x1_0000_u64;
        let segments = [segment(base, &buffer, true)];
        for arch in ARCHES {
            // With and without a GOT (or TOC, or global pointer), and for
            // Arm with most code in either mode.
            for (got, odd) in [(None, false), (Some(base + 0x800), true)] {
                let image = Binary {
                    format: Format::Elf,
                    arch: Some(arch),
                    entry: None,
                    sections: Vec::new(),
                    imports: Vec::new(),
                    exports: Vec::new(),
                    segments: segments.to_vec(),
                    seeds: vec![Seed {
                        addr: base | u64::from(odd),
                        origin: crate::Origin::Entry,
                    }],
                    slots: Vec::new(),
                    handlers: Vec::new(),
                    extents: Vec::new(),
                    got,
                    rebased: Vec::new(),
                };
                let mut decoder = Decoder::new(&image, arch);
                for at in 0..buffer.len() {
                    let addr = base + at as u64;
                    // Up to the longest encodings: m68k's 22 bytes, x86's 15.
                    for len in 1..=24 {
                        let Some(bytes) = buffer.get(at..at + len) else {
                            break;
                        };
                        for addr in [addr, addr | 1] {
                            // The decoder itself, not `decode`, which mends
                            // an empty instruction.
                            let insn = each!(&mut decoder.isa, d => d.advance(bytes, addr));
                            assert!(insn.len > 0, "{arch:?} {bytes:02x?} at {addr:#x}");
                            decoder.starts_frame(bytes);
                            decoder.literal(bytes, addr);
                            decoder.entry_of(bytes, addr);
                        }
                    }
                }
            }
        }
    }
}
