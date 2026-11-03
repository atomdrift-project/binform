//! x86 and x86-64 value tracking. iced decodes the instruction; this layer
//! records the constants, addresses and stack stores a call or syscall
//! sequence leaves, and reads an argument's registers at the site.
//!
//! x86-64 follows the SysV convention: a call's arguments in `rdi`, `rsi`,
//! `rdx`, `rcx`, `r8`, `r9`, a `syscall`'s number in `rax` and arguments in
//! `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`. 32-bit passes call arguments on the
//! stack, so only an `int 0x80` syscall (number in `eax`, arguments in `ebx`,
//! `ecx`, `edx`, `esi`, `edi`, `ebp`) resolves its arguments from registers.

use super::state::{State, Val};
use super::{RawTarget, Site, Step};
use iced_x86::{
    Code, Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic,
    OpAccess, OpKind, Register,
};

pub(crate) fn step(state: &mut State<'_>, bitness: u32, bytes: &[u8], addr: u64) -> Step {
    let mut decoder = Decoder::with_ip(bitness, bytes, addr, DecoderOptions::NONE);
    let mut insn = Instruction::default();
    decoder.decode_out(&mut insn);
    let len = u32::try_from(insn.len()).unwrap_or(1).max(1);
    if insn.is_invalid() {
        return Step::stop(len);
    }

    // A syscall reads the registers as they stand.
    if let Some(number_reg) = syscall_entry(&insn, bitness) {
        let (number_reg, args) = number_reg;
        let number = match reg(state, number_reg) {
            Val::Int(n) => n,
            _ => u64::MAX,
        };
        let args = args.iter().map(|&r| value(state, r)).collect();
        // The kernel returns in the number register; the rest survive.
        clear(state, number_reg);
        return Step {
            len,
            site: Some(Site { raw: RawTarget::Syscall(number), args }),
            barrier: false,
        };
    }

    match insn.flow_control() {
        FlowControl::Call => {
            let raw = near(&insn).map_or(RawTarget::Indirect, RawTarget::Call);
            let site = call_site(state, bitness, raw);
            clobber_call(state);
            Step { len, site: Some(site), barrier: false }
        }
        FlowControl::IndirectCall => {
            let raw = slot(&insn).map_or(RawTarget::Indirect, RawTarget::Call);
            let site = call_site(state, bitness, raw);
            clobber_call(state);
            Step { len, site: Some(site), barrier: false }
        }
        FlowControl::UnconditionalBranch
        | FlowControl::IndirectBranch
        | FlowControl::Return
        | FlowControl::Exception => Step::stop(len),
        FlowControl::ConditionalBranch => Step::go(len),
        _ => {
            track(state, &insn);
            Step::go(len)
        }
    }
}

/// The number register and argument registers of a syscall instruction, or
/// `None` when `insn` is not one.
fn syscall_entry(insn: &Instruction, bitness: u32) -> Option<(Register, [Register; 6])> {
    use Register::{EAX, EBP, EBX, ECX, EDI, EDX, ESI, R8, R9, R10, RAX, RDI, RDX, RSI};
    match insn.code() {
        Code::Syscall if bitness == 64 => Some((RAX, [RDI, RSI, RDX, R10, R8, R9])),
        Code::Int_imm8 if insn.immediate8() == 0x80 => {
            Some((EAX, [EBX, ECX, EDX, ESI, EDI, EBP]))
        }
        _ => None,
    }
}

fn call_site(state: &State<'_>, bitness: u32, raw: RawTarget) -> Site {
    use Register::{R8, R9, RCX, RDI, RDX, RSI};
    let args = if bitness == 64 {
        [RDI, RSI, RDX, RCX, R8, R9].iter().map(|&r| value(state, r)).collect()
    } else {
        Vec::new()
    };
    Site { raw, args }
}

/// The near-call target, when direct.
fn near(insn: &Instruction) -> Option<u64> {
    matches!(insn.op0_kind(), OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64)
        .then(|| insn.near_branch_target())
}

/// The fixed memory slot an indirect call goes through (`call qword
/// [rip+disp]`), the address of an import's GOT entry.
fn slot(insn: &Instruction) -> Option<u64> {
    (insn.op0_kind() == OpKind::Memory && insn.is_ip_rel_memory_operand())
        .then(|| insn.ip_rel_memory_address())
}

/// Forget the registers a call may change (the SysV caller-saved set).
fn clobber_call(state: &mut State<'_>) {
    use Register::{R8, R9, R10, R11, RAX, RCX, RDI, RDX, RSI};
    for r in [RAX, RCX, RDX, RSI, RDI, R8, R9, R10, R11] {
        clear(state, r);
    }
}

/// Model one data instruction's effect on the tracked registers and stack.
fn track(state: &mut State<'_>, insn: &Instruction) {
    let dst = insn.op0_register();
    match insn.mnemonic() {
        Mnemonic::Mov if insn.op0_kind() == OpKind::Register => {
            let value = match insn.op1_kind() {
                OpKind::Register => reg(state, insn.op1_register()),
                OpKind::Immediate8 | OpKind::Immediate16 | OpKind::Immediate32
                | OpKind::Immediate64 | OpKind::Immediate8to16 | OpKind::Immediate8to32
                | OpKind::Immediate8to64 | OpKind::Immediate32to64 => {
                    insn.try_immediate(1).ok().map_or(Val::Unknown, Val::Int)
                }
                _ => Val::Unknown,
            };
            set(state, dst, value);
        }
        // Storing a register or immediate into a stack slot.
        Mnemonic::Mov if insn.op0_kind() == OpKind::Memory => store(state, insn),
        // LEA of a fixed (rip-relative) address, or a stack address.
        Mnemonic::Lea => {
            if insn.is_ip_rel_memory_operand() {
                set(state, dst, Val::Int(insn.ip_rel_memory_address()));
            } else if insn.memory_base() == Register::RSP && insn.memory_index() == Register::None {
                if let Val::Stack(base) = reg(state, Register::RSP) {
                    #[expect(clippy::cast_possible_wrap, reason = "displacement")]
                    set(state, dst, Val::Stack(base.wrapping_add(insn.memory_displacement64() as i64)));
                } else {
                    clear(state, dst);
                }
            } else {
                clear(state, dst);
            }
        }
        // `xor r, r` is a zeroing idiom.
        Mnemonic::Xor if insn.op1_kind() == OpKind::Register && dst == insn.op1_register() => {
            set(state, dst, Val::Int(0));
        }
        // `sub`/`add rsp, imm` moves the frame pointer.
        Mnemonic::Sub | Mnemonic::Add
            if dst == Register::RSP && is_immediate(insn.op1_kind()) =>
        {
            if let (Val::Stack(off), Ok(imm)) = (reg(state, Register::RSP), insn.try_immediate(1)) {
                #[expect(clippy::cast_possible_wrap, reason = "frame delta")]
                let delta = imm as i64;
                let off = if insn.mnemonic() == Mnemonic::Sub {
                    off.wrapping_sub(delta)
                } else {
                    off.wrapping_add(delta)
                };
                set(state, Register::RSP, Val::Stack(off));
            } else {
                clear(state, Register::RSP);
            }
        }
        _ => clobber(state, insn),
    }
}

/// Store the source of a `mov [rsp+disp], src` into the stack model.
fn store(state: &mut State<'_>, insn: &Instruction) {
    if insn.memory_base() != Register::RSP || insn.memory_index() != Register::None {
        return;
    }
    let Val::Stack(base) = reg(state, Register::RSP) else {
        return;
    };
    #[expect(clippy::cast_possible_wrap, reason = "displacement")]
    let off = base.wrapping_add(insn.memory_displacement64() as i64);
    let count = u8::try_from(insn.memory_size().size()).unwrap_or(0);
    if count == 0 || count > 8 {
        return;
    }
    let value = match insn.op1_kind() {
        OpKind::Register => reg(state, insn.op1_register()),
        k if is_immediate(k) => insn.try_immediate(1).ok().map_or(Val::Unknown, Val::Int),
        _ => Val::Unknown,
    };
    match value {
        Val::Int(v) => state.store_stack(off, v, count),
        _ => state.forget_stack(off, count),
    }
}

/// Clear every register an unmodelled instruction writes.
fn clobber(state: &mut State<'_>, insn: &Instruction) {
    let mut factory = InstructionInfoFactory::new();
    for used in factory.info(insn).used_registers() {
        if matches!(
            used.access(),
            OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
        ) {
            clear(state, used.register());
        }
    }
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

/// The shared-model slot of a register, by its full 64-bit form.
fn slot_of(register: Register) -> Option<u32> {
    let full = register.full_register();
    (Register::RAX <= full && full <= Register::R15)
        .then(|| (full as u32) - (Register::RAX as u32))
}

fn reg(state: &State<'_>, register: Register) -> Val {
    let Some(s) = slot_of(register) else {
        return Val::Unknown;
    };
    // A 32-bit write zero-extends; a narrower read is only part of a value, so
    // report the whole register only when the read is 32- or 64-bit.
    match (state.get(s), register.size()) {
        (Val::Int(v), 8) => Val::Int(v),
        (Val::Int(v), 4) => Val::Int(v & 0xffff_ffff),
        (Val::Stack(off), 8) => Val::Stack(off),
        (v, _) if matches!(register, Register::RSP | Register::ESP) => v,
        _ => Val::Unknown,
    }
}

fn set(state: &mut State<'_>, register: Register, value: Val) {
    if let Some(s) = slot_of(register) {
        // A 32-bit destination zero-extends to the full register.
        let value = match (value, register.size()) {
            (Val::Int(v), 4) => Val::Int(v & 0xffff_ffff),
            (v, 8) => v,
            (v, _) if matches!(register, Register::RSP | Register::ESP) => v,
            _ => Val::Unknown,
        };
        state.set(s, value);
    }
}

fn clear(state: &mut State<'_>, register: Register) {
    if let Some(s) = slot_of(register) {
        if register == Register::RSP || register == Register::ESP {
            // The frame pointer is still a frame pointer after a push or pop
            // the walk did not fold; dropping it would lose every stack arg.
            return;
        }
        state.set(s, Val::Unknown);
    }
}

fn value(state: &State<'_>, register: Register) -> super::Value {
    match slot_of(register) {
        Some(s) => state.value(s),
        None => super::Value::Unknown,
    }
}
