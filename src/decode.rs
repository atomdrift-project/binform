//! What analysis needs from one instruction: its length, and where control
//! goes after it. Everything above this module is architecture-neutral.

use crate::{Arch, Image, Segment};

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

/// What an instruction does to registers, as far as finding a jump table
/// needs to know. Registers are numbered by the decoder; one number names a
/// register at every width.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Note {
    /// Nothing worth knowing; writes no register a table depends on.
    None,
    /// `cmp reg, imm`: a table indexed by `reg` has `imm + 1` entries.
    Compare { reg: u32, imm: u64 },
    /// `reg = addr`.
    Address { reg: u32, addr: u64 },
    /// `reg = addr`, the address of the code that reads the PC: no
    /// pointer to a function (PowerPC's `bcl 20, 31, $+4; mflr r30`).
    Pc { reg: u32, addr: u64 },
    /// `reg =` the `size`-byte value at the fixed address `mem` names: the
    /// address a GOT or TOC slot holds (a jump table's, in 32-bit PowerPC
    /// PIC code: `lwz r3, n(r30)`), sign-extended when `signed`.
    Fetch {
        reg: u32,
        mem: Mem,
        size: u8,
        signed: bool,
    },
    /// `reg = the size-byte value at mem`, sign-extended when `signed`.
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
    /// The registers the note says are written, as a mask.
    pub(crate) fn writes(self) -> u64 {
        match self {
            Self::None | Self::Push(_) | Self::PushRegister(_) => 0,
            Self::Clobber(regs) => u64::from(regs),
            Self::Compare { reg, .. }
            | Self::Address { reg, .. }
            | Self::Pc { reg, .. }
            | Self::Fetch { reg, .. }
            | Self::Load { reg, .. }
            | Self::Copy { reg, .. }
            | Self::Offset { reg, .. }
            | Self::Add { reg, .. }
            | Self::Sub { reg, .. }
            | Self::Pop(reg)
            | Self::Write(reg) => 1 << (reg & 63),
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

/// An instruction decoder for one image's architecture.
#[derive(Clone)]
pub(crate) enum Decoder {
    X86 {
        bitness: u32,
        got: Option<u64>,
    },
    Arm64(Box<crate::arm64::State>),
    Arm {
        state: crate::arm::State,
        /// Most of the code is Thumb: the sweep decodes it so.
        thumb: bool,
    },
    Mips {
        big: bool,
        wide: bool,
        /// Release 6, with compact branches in opcodes it reuses.
        r6: bool,
        /// The GOT, around the address `_gp` stands for.
        got: crate::mips::Got,
        state: crate::mips::State,
    },
    S390x(crate::s390x::State),
    Sparc {
        wide: bool,
        state: crate::sparc::State,
    },
    SuperH(crate::superh::State),
    PowerPc {
        big: bool,
        wide: bool,
        /// The TOC pointer 64-bit code keeps in `r2`.
        toc: Option<u64>,
        state: Box<crate::ppc::State>,
    },
    RiscV {
        config: crate::riscv::Config,
        state: Box<crate::riscv::State>,
    },
    LoongArch(Box<crate::loongarch::State>),
    M68k(Box<crate::m68k::State>),
    OpenRisc(Box<crate::openrisc::State>),
}

impl Decoder {
    pub(crate) fn new(image: &Image<'_>) -> Self {
        match image.arch {
            Arch::X86 => Self::X86 {
                bitness: 32,
                got: image.got,
            },
            Arch::X86_64 => Self::X86 {
                bitness: 64,
                got: None,
            },
            Arch::Arm64 => Self::Arm64(Box::default()),
            Arch::Arm => {
                // The mode most known starts are in: Thumb addresses are odd.
                let thumb = image.seeds.iter().filter(|seed| seed.addr & 1 != 0).count();
                Self::Arm {
                    state: crate::arm::State::default(),
                    thumb: 2 * thumb > image.seeds.len(),
                }
            }
            arch @ (Arch::Mips
            | Arch::MipsEl
            | Arch::Mips64
            | Arch::Mips64El
            | Arch::MipsR6
            | Arch::MipsR6El
            | Arch::Mips64R6
            | Arch::Mips64R6El) => Self::Mips {
                big: arch.big_endian(),
                wide: arch.address_width() == 8,
                r6: arch.mips_r6(),
                got: crate::mips::Got::new(image.got, &image.segments),
                state: crate::mips::State::default(),
            },
            Arch::S390x => Self::S390x(crate::s390x::State::default()),
            Arch::Sparc => Self::Sparc {
                wide: false,
                state: crate::sparc::State::default(),
            },
            Arch::Sparc64 => Self::Sparc {
                wide: true,
                state: crate::sparc::State::default(),
            },
            Arch::SuperH => Self::SuperH(crate::superh::State::default()),
            arch @ (Arch::PowerPc | Arch::PowerPc64 | Arch::PowerPc64El) => Self::PowerPc {
                big: arch.big_endian(),
                wide: arch.address_width() == 8,
                toc: image.got,
                state: Box::default(),
            },
            arch @ (Arch::RiscV32 | Arch::RiscV64) => Self::RiscV {
                config: crate::riscv::Config {
                    wide: arch == Arch::RiscV64,
                    gp: image.got,
                },
                state: Box::default(),
            },
            Arch::LoongArch64 => Self::LoongArch(Box::default()),
            Arch::M68k => Self::M68k(Box::default()),
            Arch::OpenRisc => Self::OpenRisc(Box::default()),
        }
    }

    /// Forget what earlier instructions left in registers. Called wherever
    /// control may arrive from elsewhere.
    pub(crate) fn reset(&mut self) {
        match self {
            Self::Arm64(state) => **state = crate::arm64::State::default(),
            Self::Arm { state, .. } => *state = crate::arm::State::default(),
            Self::Mips { state, .. } => *state = crate::mips::State::default(),
            Self::S390x(state) => *state = crate::s390x::State::default(),
            Self::Sparc { state, .. } => *state = crate::sparc::State::default(),
            Self::SuperH(state) => *state = crate::superh::State::default(),
            Self::PowerPc { state, .. } => **state = crate::ppc::State::default(),
            Self::RiscV { state, .. } => **state = crate::riscv::State::default(),
            Self::LoongArch(state) => **state = crate::loongarch::State::default(),
            Self::M68k(state) => **state = crate::m68k::State::default(),
            Self::OpenRisc(state) => **state = crate::openrisc::State::default(),
            _ => {}
        }
    }

    /// Decode the instruction at the start of `bytes`, mapped at `addr`.
    pub(crate) fn decode(&mut self, bytes: &[u8], addr: u64) -> Insn {
        match self {
            Self::X86 { bitness, got } => crate::x86::decode(*bitness, *got, bytes, addr),
            Self::Arm64(state) => crate::arm64::decode(state, bytes, addr),
            Self::Arm { state, .. } => crate::arm::decode(state, bytes, addr),
            Self::Mips {
                big,
                wide,
                r6,
                got,
                state,
            } => crate::mips::decode(state, got, (*big, *wide, *r6), bytes, addr),
            Self::S390x(state) => crate::s390x::decode(state, bytes, addr),
            Self::Sparc { wide, state } => crate::sparc::decode(state, *wide, bytes, addr),
            Self::SuperH(state) => crate::superh::decode(state, bytes, addr),
            Self::PowerPc {
                big,
                wide,
                toc,
                state,
            } => crate::ppc::decode(state, (*big, *wide, *toc), bytes, addr),
            Self::RiscV { config, state } => crate::riscv::decode(state, *config, bytes, addr),
            Self::LoongArch(state) => crate::loongarch::decode(state, bytes, addr),
            Self::M68k(state) => crate::m68k::decode(state, bytes, addr),
            Self::OpenRisc(state) => crate::openrisc::decode(state, bytes, addr),
        }
    }

    /// Whether a GOT slot of a function of the binary holds its address in
    /// the file: MIPS GOTs do, without relocations to say so.
    pub(crate) const fn slots_hold_targets(&self) -> bool {
        matches!(self, Self::Mips { .. })
    }

    /// Bytes in an address.
    pub(crate) fn address_width(&self) -> u8 {
        match self {
            Self::X86 { bitness: 32, .. }
            | Self::Arm { .. }
            | Self::Mips { wide: false, .. }
            | Self::Sparc { wide: false, .. }
            | Self::PowerPc { wide: false, .. }
            | Self::SuperH(_)
            | Self::M68k(_)
            | Self::OpenRisc(_) => 4,
            Self::RiscV { config, .. } if !config.wide => 4,
            Self::X86 { .. }
            | Self::Arm64(_)
            | Self::Mips { .. }
            | Self::S390x(_)
            | Self::Sparc { .. }
            | Self::PowerPc { .. }
            | Self::RiscV { .. }
            | Self::LoongArch(_) => 8,
        }
    }

    /// Instructions start at multiples of this, in the mode the sweep
    /// decodes.
    pub(crate) fn alignment(&self) -> u64 {
        match self {
            Self::X86 { .. } => 1,
            Self::S390x(_)
            | Self::SuperH(_)
            | Self::Arm { thumb: true, .. }
            | Self::RiscV { .. }
            | Self::M68k(_) => 2,
            Self::Arm64(_)
            | Self::Arm { .. }
            | Self::Mips { .. }
            | Self::Sparc { .. }
            | Self::PowerPc { .. }
            | Self::LoongArch(_)
            | Self::OpenRisc(_) => 4,
        }
    }

    /// What the sweep adds to an address to decode it in the mode most code
    /// is in: 1 for Thumb, whose addresses are odd.
    pub(crate) fn sweep_mode(&self) -> u64 {
        u64::from(matches!(self, Self::Arm { thumb: true, .. }))
    }

    /// Whether a stub may compute its slot's address before jumping
    /// through it, as on the fixed-width RISC sets, rather than only pad.
    pub(crate) fn stub_arithmetic(&self) -> bool {
        !matches!(self, Self::X86 { .. })
    }

    /// The register a 32-bit PC thunk at the start of `bytes` returns the
    /// caller's address in.
    /// What a call at `call` to a PC thunk at the start of `bytes` leaves in
    /// a register, returning to `next`; `None` for any other callee. On
    /// i386 the register holds `next`; SPARC's thunk adds the call's own
    /// address to it.
    pub(crate) fn pc_thunk(&self, bytes: &[u8], call: u64, next: u64) -> Option<Note> {
        match self {
            Self::X86 { bitness: 32, .. } => {
                crate::x86::pc_thunk(bytes).map(|reg| Note::Address { reg, addr: next })
            }
            Self::Sparc { .. } => crate::sparc::pc_thunk(bytes).map(|reg| Note::Offset {
                reg,
                src: reg,
                imm: call,
            }),
            _ => None,
        }
    }

    /// The registers, as a mask, a callee leaves as they were, as far as
    /// a jump table after the call is concerned.
    pub(crate) const fn call_preserved(&self) -> u32 {
        match self {
            Self::Sparc { .. } => crate::sparc::CALL_PRESERVED,
            _ => 0,
        }
    }

    /// Whether a fixed address an instruction loads into a register is, when
    /// it points at code, a function whose address the program takes: true
    /// of SuperH's literal-pool loads, which hold data, callees and
    /// callbacks (other sets also note addresses inside the function).
    pub(crate) const fn notes_pointers(&self) -> bool {
        matches!(
            self,
            Self::SuperH(_)
                | Self::PowerPc { wide: false, .. }
                | Self::LoongArch(_)
                | Self::M68k(_)
                | Self::OpenRisc(_)
        )
    }

    /// Whether transfers have delay slots, whose note a call's or jump's
    /// is: it applies before the target.
    pub(crate) const fn delay_slots(&self) -> bool {
        matches!(
            self,
            Self::Sparc { .. } | Self::Mips { .. } | Self::OpenRisc(_)
        )
    }

    /// The register that carries a call's `n`th argument (from zero) under
    /// the System V and A64 conventions; `None` when it goes on the stack.
    pub(crate) fn argument(&self, n: usize) -> Option<u32> {
        match self {
            Self::X86 { bitness: 64, .. } => crate::x86::argument(n),
            Self::X86 { .. } => None,
            Self::Arm64(_) => u32::try_from(n).ok().filter(|&n| n < 8),
            // No decoder below tracks the registers arguments travel in.
            _ => None,
        }
    }

    /// Whether `bytes` begin by setting up a frame pointer, as only a
    /// function's first instructions do.
    pub(crate) fn starts_frame(&self, bytes: &[u8]) -> bool {
        match self {
            Self::X86 { bitness, .. } => crate::x86::starts_frame(*bitness, bytes),
            Self::Arm64(_) => crate::arm64::starts_frame(bytes),
            Self::Arm { thumb, .. } => crate::arm::starts_frame(*thumb, bytes),
            Self::SuperH(_) => crate::superh::starts_frame(bytes),
            Self::S390x(_) => crate::s390x::starts_frame(bytes),
            Self::PowerPc { big, .. } => crate::ppc::starts_frame(*big, bytes),
            Self::RiscV { .. } => crate::riscv::starts_frame(bytes),
            Self::LoongArch(_) => crate::loongarch::starts_frame(bytes),
            Self::M68k(_) => crate::m68k::starts_frame(bytes),
            Self::OpenRisc(_) => crate::openrisc::starts_frame(bytes),
            _ => false,
        }
    }

    /// Whether `bytes` can only be a function's first instructions: 64-bit
    /// ELFv2's global entry, which sets the TOC pointer from the function's
    /// own address.
    pub(crate) fn starts_function(&self, bytes: &[u8]) -> bool {
        match self {
            Self::PowerPc {
                big, wide: true, ..
            } => crate::ppc::global_entry(*big, bytes),
            _ => false,
        }
    }

    /// Where the function entered at `addr` starts, given the eight bytes
    /// before it: 64-bit ELFv2 code enters a function eight bytes in from
    /// within its module, past the instructions that set the TOC pointer.
    pub(crate) fn global_entry(&self, addr: u64, before: &[u8]) -> u64 {
        match self {
            Self::PowerPc {
                big, wide: true, ..
            } if crate::ppc::global_entry(*big, before) => addr.wrapping_sub(8),
            _ => addr,
        }
    }
}

/// The mapped segments of an image, searchable by address.
pub(crate) struct Memory<'a> {
    /// Sorted by address.
    segments: Vec<Span<'a>>,
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
        Self {
            segments,
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
        let end = self
            .segments
            .partition_point(|segment| segment.addr <= addr);
        // Overlapping segments (a malformed header can declare them) fall
        // back to the nearest one below that still contains `addr`.
        self.segments.get(..end)?.iter().rev().find_map(|segment| {
            let offset = usize::try_from(addr.checked_sub(segment.addr)?).ok()?;
            let bytes = segment
                .bytes
                .get(offset..)
                .filter(|bytes| !bytes.is_empty())?;
            Some((bytes, segment.executable))
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
        let bytes = bytes.get(..usize::from(size)).filter(|_| size <= 8)?;
        let word = |value: u64, &byte: &u8| value << 8 | u64::from(byte);
        Some(if self.big {
            bytes.iter().fold(0, word)
        } else {
            bytes.iter().rev().fold(0, word)
        })
    }

    /// Whether words are stored most significant byte first.
    pub(crate) fn big_endian(&self) -> bool {
        self.big
    }

    pub(crate) fn code_segments(&self) -> impl Iterator<Item = &Span<'a>> {
        self.segments.iter().filter(|segment| segment.executable)
    }
}
