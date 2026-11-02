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
    /// Jump through the pointer stored at a fixed address.
    JumpSlot(u64),
    /// Jump through the pointer stored at a computed address: a jump table,
    /// when the instructions before it say so.
    JumpMemory(Mem),
    /// Jump to the address in a register: a jump table, when the
    /// instructions before it say so.
    JumpRegister(u32),
    /// Jump somewhere that cannot be followed.
    JumpIndirect,
    /// Return.
    Return,
    /// Trap, halt, or bytes that do not decode.
    Stop,
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
    /// `reg = the size-byte value at mem`, sign-extended when `signed`.
    Load {
        reg: u32,
        mem: Mem,
        size: u8,
        signed: bool,
    },
    /// `reg = src`.
    Copy { reg: u32, src: u32 },
    /// `reg += src`.
    Add { reg: u32, src: u32 },
    /// `reg` changes some other way.
    Write(u32),
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
pub(crate) enum Decoder {
    X86 { bitness: u32, got: Option<u64> },
    Arm64(Box<crate::arm64::State>),
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
        }
    }

    /// Forget what earlier instructions left in registers. Called wherever
    /// control may arrive from elsewhere.
    pub(crate) fn reset(&mut self) {
        if let Self::Arm64(state) = self {
            **state = crate::arm64::State::default();
        }
    }

    /// Decode the instruction at the start of `bytes`, mapped at `addr`.
    pub(crate) fn decode(&mut self, bytes: &[u8], addr: u64) -> Insn {
        match self {
            Self::X86 { bitness, got } => crate::x86::decode(*bitness, *got, bytes, addr),
            Self::Arm64(state) => crate::arm64::decode(state, bytes, addr),
        }
    }

    /// Bytes in an address.
    pub(crate) fn address_width(&self) -> u8 {
        match self {
            Self::X86 { bitness: 32, .. } => 4,
            Self::X86 { .. } | Self::Arm64(_) => 8,
        }
    }

    /// Instructions start at multiples of this.
    pub(crate) fn alignment(&self) -> u64 {
        match self {
            Self::X86 { .. } => 1,
            Self::Arm64(_) => 4,
        }
    }

    /// Whether `bytes` begin by setting up a frame pointer, as only a
    /// function's first instructions do.
    pub(crate) fn starts_frame(&self, bytes: &[u8]) -> bool {
        match self {
            Self::X86 { bitness, .. } => crate::x86::starts_frame(*bitness, bytes),
            Self::Arm64(_) => crate::arm64::starts_frame(bytes),
        }
    }
}

/// The mapped segments of an image, searchable by address.
pub(crate) struct Memory<'a> {
    /// Sorted by address.
    segments: Vec<Segment<'a>>,
}

impl<'a> Memory<'a> {
    pub(crate) fn new(segments: &[Segment<'a>]) -> Self {
        let mut segments: Vec<Segment<'a>> = segments
            .iter()
            .filter(|segment| !segment.bytes.is_empty())
            .copied()
            .collect();
        segments.sort_by_key(|segment| segment.addr);
        Self { segments }
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
        self.at(addr)
            .and_then(|(bytes, executable)| executable.then_some(bytes))
    }

    pub(crate) fn is_code(&self, addr: u64) -> bool {
        self.code(addr).is_some()
    }

    /// The little-endian unsigned integer of `size` bytes, at most eight,
    /// stored at `addr`.
    pub(crate) fn read(&self, addr: u64, size: u8) -> Option<u64> {
        let (bytes, _) = self.at(addr)?;
        let bytes = bytes.get(..usize::from(size)).filter(|_| size <= 8)?;
        Some(
            bytes
                .iter()
                .rev()
                .fold(0, |value, &byte| value << 8 | u64::from(byte)),
        )
    }

    pub(crate) fn code_segments(&self) -> impl Iterator<Item = &Segment<'a>> {
        self.segments.iter().filter(|segment| segment.executable)
    }
}
