//! x86 and x86-64 value tracking. iced decodes the instruction; this layer
//! records the constants, addresses and stack stores a call or syscall
//! sequence leaves, and reads the argument registers at the site.
//!
//! x86-64 follows the SysV convention: a call's arguments in `rdi`, `rsi`,
//! `rdx`, `rcx`, `r8`, `r9`, a `syscall`'s number in `rax` and arguments in
//! `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`. 32-bit code passes call arguments
//! on the stack, so only an `int 0x80` syscall (number in `eax`, arguments
//! in `ebx`, `ecx`, `edx`, `esi`, `edi`, `ebp`) resolves its arguments.
//!
//! Registers are numbered as iced orders the 64-bit ones, `rax` to `r15`.

use super::state::{State, Val};
use super::{RawTarget, Site, Step, Tracker, Value};
use iced_x86::{
    Code, Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic,
    OpAccess, OpKind, Register,
};

/// `rsp` (or `esp`): the fifth register in iced's order.
const SP: u32 = 4;

pub(crate) struct X86<'a> {
    bitness: u32,
    mode: Mode,
    /// Decodes the code being walked.
    decoder: Option<Decoder<'a>>,
    info: InstructionInfoFactory,
}

impl X86<'_> {
    pub(crate) fn new(bitness: u32) -> Self {
        Self {
            bitness,
            mode: Mode {
                full: if bitness == 64 { 8 } else { 4 },
            },
            decoder: None,
            info: InstructionInfoFactory::new(),
        }
    }
}

impl<'a> Tracker<'a> for X86<'a> {
    fn sp(&self) -> u32 {
        SP
    }

    fn pointer(&self) -> u8 {
        if self.bitness == 64 { 8 } else { 4 }
    }

    fn begin(&mut self, code: &'a [u8], start: u64) {
        self.decoder = Some(Decoder::with_ip(
            self.bitness,
            code,
            start,
            DecoderOptions::NONE,
        ));
    }

    fn reset(&mut self) {}

    fn step(&mut self, state: &mut State<'_>, at: usize, addr: u64) -> Step {
        let Some(decoder) = self.decoder.as_mut() else {
            return Step::stop(1);
        };
        if decoder.set_position(at).is_err() {
            return Step::stop(1);
        }
        decoder.set_ip(addr);
        let insn = decoder.decode();
        let len = u32::try_from(insn.len()).unwrap_or(1);
        if insn.is_invalid() {
            return Step::stop(len);
        }
        let mode = self.mode;

        // A syscall reads the registers as they stand.
        if let Some((nr, args)) = syscall_entry(&insn, self.bitness) {
            let number = match mode.reg(state, nr) {
                Val::Int(n) => Some(n),
                _ => None,
            };
            let args = args.iter().map(|&r| mode.value(state, r)).collect();
            // The kernel returns in the number register; the rest survive.
            mode.set(state, nr, Val::Unknown);
            return Step::site(
                len,
                Site {
                    raw: RawTarget::Syscall(number),
                    args,
                },
            );
        }

        match insn.flow_control() {
            FlowControl::Call | FlowControl::IndirectCall => {
                use Register::{R8, R9, R10, R11, RAX, RCX, RDI, RDX, RSI};
                let raw = if let Some(to) = near(&insn) {
                    RawTarget::Call(to)
                } else if let Some(slot) = got_slot(&insn) {
                    RawTarget::Slot(slot)
                } else {
                    RawTarget::Indirect
                };
                let args = if self.bitness == 64 {
                    [RDI, RSI, RDX, RCX, R8, R9]
                        .iter()
                        .map(|&r| mode.value(state, r))
                        .collect()
                } else {
                    Vec::new()
                };
                // The SysV caller-saved registers, and the callee's frame
                // below the stack pointer.
                for r in [RAX, RCX, RDX, RSI, RDI, R8, R9, R10, R11] {
                    mode.set(state, r, Val::Unknown);
                }
                state.forget_below_sp();
                Step::site(len, Site { raw, args })
            }
            FlowControl::UnconditionalBranch
            | FlowControl::IndirectBranch
            | FlowControl::Return
            | FlowControl::Exception => Step::stop(len),
            FlowControl::ConditionalBranch => Step::go(len),
            _ => {
                self.track(state, &insn);
                Step::go(len)
            }
        }
    }
}

/// The number register and argument registers of a syscall instruction, or
/// `None` when `insn` is not one.
fn syscall_entry(insn: &Instruction, bitness: u32) -> Option<(Register, [Register; 6])> {
    use Register::{EAX, EBP, EBX, ECX, EDI, EDX, ESI, R8, R9, R10, RAX, RDI, RDX, RSI};
    match insn.code() {
        Code::Syscall if bitness == 64 => Some((RAX, [RDI, RSI, RDX, R10, R8, R9])),
        Code::Int_imm8 if insn.immediate8() == 0x80 => Some((EAX, [EBX, ECX, EDX, ESI, EDI, EBP])),
        _ => None,
    }
}

/// The near-call target, when direct.
fn near(insn: &Instruction) -> Option<u64> {
    matches!(
        insn.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    )
    .then(|| insn.near_branch_target())
}

/// The fixed memory slot an indirect call goes through (`call qword
/// [rip+disp]`): an import's GOT entry, or some other pointer.
fn got_slot(insn: &Instruction) -> Option<u64> {
    (insn.op0_kind() == OpKind::Memory && insn.is_ip_rel_memory_operand())
        .then(|| insn.ip_rel_memory_address())
}

impl X86<'_> {
    /// Model one data instruction's effect on the tracked registers and
    /// frame.
    fn track(&mut self, state: &mut State<'_>, insn: &Instruction) {
        let mode = self.mode;
        let dst = insn.op0_register();
        let increment = insn.stack_pointer_increment();
        match insn.mnemonic() {
            Mnemonic::Mov if insn.op0_kind() == OpKind::Register => {
                let value = mode.operand(state, insn, 1);
                mode.set(state, dst, value);
            }
            Mnemonic::Mov if insn.op0_kind() == OpKind::Memory => {
                let value = mode.operand(state, insn, 1);
                if let Some(off) = mode.frame_offset(state, insn) {
                    state.store(off, value, mem_width(insn));
                } else if matches!(mode.reg(state, insn.memory_base()), Val::Stack(_)) {
                    // Into the frame, at an offset an index register picks.
                    state.forget_frame();
                }
            }
            Mnemonic::Lea => {
                let value = if insn.is_ip_rel_memory_operand() {
                    Val::Int(insn.ip_rel_memory_address())
                } else {
                    mode.frame_offset(state, insn)
                        .map_or(Val::Unknown, Val::Stack)
                };
                mode.set(state, dst, value);
            }
            // `xor r, r` is a zeroing idiom.
            Mnemonic::Xor if insn.op1_kind() == OpKind::Register && dst == insn.op1_register() => {
                mode.set(state, dst, Val::Int(0));
            }
            Mnemonic::Push if increment < 0 => {
                let value = mode.operand(state, insn, 0);
                let sp = state.get(SP).plus(i64::from(increment));
                state.set(SP, sp);
                if let Val::Stack(off) = sp {
                    state.store(off, value, width(increment));
                }
            }
            Mnemonic::Pop if insn.op0_kind() == OpKind::Register => {
                let sp = state.get(SP);
                let value = match sp {
                    Val::Stack(off) => state.load(off, width(increment)),
                    _ => Val::Unknown,
                };
                state.set(SP, sp.plus(i64::from(increment)));
                mode.set(state, dst, value);
            }
            // `sub`/`add rsp, imm` moves the stack pointer.
            Mnemonic::Sub | Mnemonic::Add
                if reg_index(dst) == Some(SP)
                    && dst.size() == mode.full
                    && is_immediate(insn.op1_kind()) =>
            {
                let delta = insn.try_immediate(1).map_or(0, |imm| mode.signed(imm));
                let delta = if insn.mnemonic() == Mnemonic::Sub {
                    delta.wrapping_neg()
                } else {
                    delta
                };
                state.set(SP, state.get(SP).plus(delta));
            }
            _ => self.clobber(state, insn),
        }
    }

    /// Clear every register an unmodelled instruction writes, and forget the
    /// frame bytes it writes.
    fn clobber(&mut self, state: &mut State<'_>, insn: &Instruction) {
        let mode = self.mode;
        let writes = |access: OpAccess| {
            matches!(
                access,
                OpAccess::Write
                    | OpAccess::CondWrite
                    | OpAccess::ReadWrite
                    | OpAccess::ReadCondWrite
            )
        };
        let info = self.info.info(insn);
        for used in info
            .used_memory()
            .iter()
            .filter(|used| writes(used.access()))
        {
            let Val::Stack(base) = mode.reg(state, used.base()) else {
                continue;
            };
            let width = u16::try_from(used.memory_size().size()).unwrap_or(0);
            if used.index() == Register::None && width != 0 && !insn.has_rep_prefix() {
                state.forget(base.wrapping_add(mode.signed(used.displacement())), width);
            } else {
                state.forget_frame();
            }
        }
        for used in info
            .used_registers()
            .iter()
            .filter(|used| writes(used.access()))
        {
            if let Some(r) = reg_index(used.register()) {
                state.clear(r);
            }
        }
    }
}

/// The register width of the code: how wide a full register is, and so how
/// reads and writes of narrower ones behave.
#[derive(Clone, Copy)]
struct Mode {
    /// Bytes in a full-width register: 8, or 4 in 32-bit code.
    full: usize,
}

impl Mode {
    /// What a read of `register` gives: the whole value for a full-width
    /// read, the low half of a constant for a 32-bit read of a 64-bit
    /// register, and nothing known for a narrower one.
    fn reg(self, state: &State<'_>, register: Register) -> Val {
        let Some(r) = reg_index(register) else {
            return Val::Unknown;
        };
        match (state.get(r), register.size()) {
            (v, size) if size == self.full => v,
            (v @ Val::Int(_), 4) => v.low32(),
            _ => Val::Unknown,
        }
    }

    /// Write `value` to `register`. A 32-bit write zero-extends to the full
    /// 64-bit register; a narrower one leaves a value the model cannot tell.
    fn set(self, state: &mut State<'_>, register: Register, value: Val) {
        let Some(r) = reg_index(register) else {
            return;
        };
        let value = match (value, register.size()) {
            (v, size) if size == self.full => v,
            (v @ Val::Int(_), 4) => v.low32(),
            _ => Val::Unknown,
        };
        state.set(r, value);
    }

    fn value(self, state: &State<'_>, register: Register) -> Value {
        reg_index(register).map_or(Value::Unknown, |r| state.value(r))
    }

    /// The value operand `n` of `insn` reads: a register, an immediate, or
    /// a load from the frame.
    fn operand(self, state: &State<'_>, insn: &Instruction, n: u32) -> Val {
        match insn.op_kind(n) {
            OpKind::Register => self.reg(state, insn.op_register(n)),
            OpKind::Memory => self
                .frame_offset(state, insn)
                .map_or(Val::Unknown, |off| state.load(off, mem_width(insn))),
            k if is_immediate(k) => insn.try_immediate(n).map_or(Val::Unknown, Val::Int),
            _ => Val::Unknown,
        }
    }

    /// The frame offset a memory operand addresses, when its base register
    /// holds a stack pointer and it has no index: `[rsp±n]`, or `[rbp±n]` in
    /// a frame.
    fn frame_offset(self, state: &State<'_>, insn: &Instruction) -> Option<i64> {
        if insn.memory_index() != Register::None {
            return None;
        }
        let Val::Stack(base) = self.reg(state, insn.memory_base()) else {
            return None;
        };
        Some(base.wrapping_add(self.signed(insn.memory_displacement64())))
    }

    /// A displacement or immediate as a signed value of the register width:
    /// in 32-bit code, `0xffff_fff0` is -16.
    fn signed(self, v: u64) -> i64 {
        if self.full == 8 {
            v.cast_signed()
        } else {
            i64::from(u32::try_from(v & 0xffff_ffff).unwrap_or(0).cast_signed())
        }
    }
}

/// The model's number for a general register, by its full-width form.
fn reg_index(register: Register) -> Option<u32> {
    let full = register.full_register();
    (Register::RAX <= full && full <= Register::R15)
        .then(|| (full as u32).wrapping_sub(Register::RAX as u32))
}

/// The bytes a push or pop that moves the stack pointer by `increment`
/// moves.
fn width(increment: i32) -> u8 {
    u8::try_from(increment.unsigned_abs()).unwrap_or(0)
}

/// The bytes a memory operand covers.
fn mem_width(insn: &Instruction) -> u8 {
    u8::try_from(insn.memory_size().size()).unwrap_or(0)
}

/// Whether an operand is an immediate.
fn is_immediate(kind: OpKind) -> bool {
    matches!(
        kind,
        OpKind::Immediate8
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64
    )
}
