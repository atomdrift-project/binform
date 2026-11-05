//! x86 and x86-64, through `iced-x86`.

use crate::isa::{Extend, Flow, Insn, Mem, Note};
use iced_x86::{Code, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};

pub(crate) fn decode(bitness: u32, got: Option<u64>, bytes: &[u8], addr: u64) -> Insn {
    let instruction =
        iced_x86::Decoder::with_ip(bitness, bytes, addr, DecoderOptions::NONE).decode();
    if instruction.is_invalid() {
        return Insn::new(1, Flow::Invalid);
    }
    let len = u32::try_from(instruction.len()).unwrap_or(1).max(1);
    let next = addr.wrapping_add(u64::from(len));
    // A call to the next instruction only pushes its address: 32-bit
    // position-independent code reads the address back with a `pop`.
    if instruction.flow_control() == FlowControl::Call && near(&instruction) == Some(next) {
        return Insn::note(len, Note::Push(next));
    }
    let flow = match instruction.flow_control() {
        FlowControl::Next if instruction.mnemonic() == Mnemonic::Hlt => Flow::Stop,
        FlowControl::Next => Flow::Next,
        // A far jump leaves the code segment: nothing to follow.
        FlowControl::UnconditionalBranch => {
            near(&instruction).map_or(Flow::JumpIndirect, Flow::Jump)
        }
        FlowControl::ConditionalBranch => near(&instruction).map_or(Flow::Next, Flow::Branch),
        FlowControl::IndirectBranch => slot(&instruction, bitness, got).map_or_else(
            || match instruction.op0_kind() {
                OpKind::Memory => Flow::JumpMemory(mem(&instruction, bitness)),
                OpKind::Register => Flow::JumpRegister(register_id(instruction.op0_register())),
                _ => Flow::JumpIndirect,
            },
            Flow::JumpSlot,
        ),
        FlowControl::Return => Flow::Return,
        // `syscall`, `sysenter` and the virtualization calls come back to the
        // next instruction.
        FlowControl::Call => near(&instruction).map_or(Flow::Next, Flow::Call),
        FlowControl::IndirectCall => {
            slot(&instruction, bitness, got).map_or(Flow::CallIndirect, Flow::CallSlot)
        }
        FlowControl::Interrupt => match instruction.code() {
            Code::Int3 | Code::Int1 => Flow::Stop,
            _ => Flow::Next,
        },
        FlowControl::XbeginXabortXend => Flow::Next,
        FlowControl::Exception => Flow::Stop,
    };
    // A branch reads its operand; only straight-line code changes registers
    // a jump table depends on.
    let note = if instruction.flow_control() == FlowControl::Next {
        note(&instruction, bitness)
    } else {
        Note::None
    };
    Insn {
        note,
        pad: matches!(
            instruction.mnemonic(),
            Mnemonic::Endbr32 | Mnemonic::Endbr64 | Mnemonic::Nop
        ),
        ..Insn::new(len, flow)
    }
}

/// `push ebp; mov ebp, esp` and its 64-bit form, after the optional
/// hot-patch `mov edi, edi` or an `endbr`.
pub(crate) fn starts_frame(bitness: u32, bytes: &[u8]) -> bool {
    let bytes = [
        &[0xf3, 0x0f, 0x1e, 0xfa][..],
        &[0xf3, 0x0f, 0x1e, 0xfb],
        &[0x8b, 0xff],
    ]
    .into_iter()
    .find_map(|prefix| bytes.strip_prefix(prefix))
    .unwrap_or(bytes);
    let frame: &[&[u8]] = if bitness == 64 {
        &[&[0x55, 0x48, 0x89, 0xe5], &[0x55, 0x48, 0x8b, 0xec]]
    } else {
        &[&[0x55, 0x89, 0xe5], &[0x55, 0x8b, 0xec]]
    };
    frame.iter().any(|frame| bytes.starts_with(frame))
}

fn near(instruction: &Instruction) -> Option<u64> {
    matches!(
        instruction.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    )
    .then(|| instruction.near_branch_target())
}

/// The register a 32-bit PC thunk (`mov reg, [esp]; ret`) at the start of
/// `bytes` returns the caller's address in.
pub(crate) fn pc_thunk(bytes: &[u8]) -> Option<u32> {
    // `reg` numbers the register as `register_id` does.
    match *bytes.get(..4)? {
        [0x8b, modrm, 0x24, 0xc3] if modrm & 0xc7 == 0x04 => Some(u32::from(modrm >> 3 & 7)),
        _ => None,
    }
}

/// The register of the System V x86-64 convention's `n`th integer argument.
pub(crate) fn argument(n: usize) -> Option<u32> {
    [Register::RDI, Register::RSI, Register::RDX, Register::RCX]
        .get(n)
        .map(|&register| register_id(register))
}

/// What the instruction does to its first operand, when that is a register.
/// Implicit writes (`mul`, `cpuid`, string instructions) go unnoticed; none
/// sits between a jump-table bound and its jump.
fn note(instruction: &Instruction, bitness: u32) -> Note {
    if instruction.mnemonic() == Mnemonic::Push && is_immediate(instruction.op0_kind()) {
        return Note::Push(instruction.immediate(0));
    }
    if instruction.op_count() == 0 || instruction.op0_kind() != OpKind::Register {
        return Note::None;
    }
    let reg = register_id(instruction.op0_register());
    // Writing a vector, segment or control register changes no register
    // a jump table depends on.
    if reg == OTHER {
        return Note::None;
    }
    let source = instruction.op1_kind();
    // A 32-bit write in 64-bit code truncates an address.
    let whole = bitness == 32 || instruction.op0_register().size() == 8;
    match instruction.mnemonic() {
        Mnemonic::Cmp if is_immediate(source) => Note::Compare {
            reg,
            imm: instruction.immediate(1),
        },
        Mnemonic::Push => Note::PushRegister(reg),
        Mnemonic::Pop => Note::Pop(reg),
        // Read their first operand without writing it.
        Mnemonic::Cmp | Mnemonic::Test | Mnemonic::Bt => Note::None,
        Mnemonic::Lea => match mem(instruction, bitness) {
            Mem {
                base: None,
                index: None,
                disp,
                ..
            } => Note::Address { reg, addr: disp },
            Mem {
                base: Some(src),
                index: None,
                disp,
                ..
            } if whole => Note::Offset {
                reg,
                src,
                imm: disp,
            },
            _ => Note::Write(reg),
        },
        Mnemonic::Add if is_immediate(source) && whole => Note::Offset {
            reg,
            src: reg,
            imm: instruction.immediate(1),
        },
        // A 32-bit move zero-extends: the value is whole either way.
        Mnemonic::Mov if is_immediate(source) && instruction.op0_register().size() >= 4 => {
            Note::Address {
                reg,
                addr: instruction.immediate(1),
            }
        }
        Mnemonic::Mov | Mnemonic::Movsxd if source == OpKind::Register => Note::Copy {
            reg,
            src: register_id(instruction.op1_register()),
        },
        Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Movsx | Mnemonic::Movsxd
            if source == OpKind::Memory =>
        {
            match u8::try_from(instruction.memory_size().size()) {
                Ok(size) => Note::Load {
                    reg,
                    mem: mem(instruction, bitness),
                    size,
                    signed: matches!(instruction.mnemonic(), Mnemonic::Movsx | Mnemonic::Movsxd),
                },
                Err(_) => Note::Write(reg),
            }
        }
        Mnemonic::Add if source == OpKind::Register => Note::Add {
            reg,
            base: reg,
            index: register_id(instruction.op1_register()),
            shift: 0,
            extend: Extend::None,
        },
        _ => Note::Write(reg),
    }
}

fn is_immediate(kind: OpKind) -> bool {
    matches!(
        kind,
        OpKind::Immediate8
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate32to64
            | OpKind::Immediate64
    )
}

/// The instruction's memory operand. PC-relative addresses are resolved.
fn mem(instruction: &Instruction, bitness: u32) -> Mem {
    if instruction.is_ip_rel_memory_operand() {
        return Mem {
            base: None,
            index: None,
            scale: 1,
            disp: instruction.ip_rel_memory_address(),
        };
    }
    let id = |register: Register| (register != Register::None).then(|| register_id(register));
    Mem {
        base: id(instruction.memory_base()),
        index: id(instruction.memory_index()),
        scale: u8::try_from(instruction.memory_index_scale()).unwrap_or(0),
        disp: displacement(instruction, bitness),
    }
}

/// The fixed address a memory-indirect branch loads its target from:
/// `[abs]`, `[rip + disp]`, or in 32-bit PIC code `[ebx + disp]` with `ebx`
/// holding the GOT.
fn slot(instruction: &Instruction, bitness: u32, got: Option<u64>) -> Option<u64> {
    if instruction.op0_kind() != OpKind::Memory {
        return None;
    }
    if instruction.is_ip_rel_memory_operand() {
        return Some(instruction.ip_rel_memory_address());
    }
    match (instruction.memory_base(), instruction.memory_index()) {
        (Register::None, Register::None) => Some(displacement(instruction, bitness)),
        (Register::EBX, Register::None) if bitness == 32 => got.map(|got| {
            let got = u32::try_from(got).unwrap_or(u32::MAX);
            u64::from(got.wrapping_add(instruction.memory_displacement32()))
        }),
        _ => None,
    }
}

fn displacement(instruction: &Instruction, bitness: u32) -> u64 {
    if bitness == 64 {
        instruction.memory_displacement64()
    } else {
        u64::from(instruction.memory_displacement32())
    }
}

/// The id of every register but the 16 general ones, whose values no
/// jump table depends on.
const OTHER: u32 = 16;

/// One id per general register, whatever width names it, numbered as the
/// encoding numbers them: `al`, `ax`, `eax` and `rax` are register 0, `r15`
/// is 15. Any other register is [`OTHER`].
fn register_id(register: Register) -> u32 {
    let index = (register.full_register() as u32).wrapping_sub(Register::RAX as u32);
    if index < 16 { index } else { OTHER }
}

/// The x86 decoder: 32- or 64-bit, and the GOT address 32-bit PIC stubs
/// jump through, when known. It keeps nothing between instructions.
#[derive(Clone, Debug)]
pub(crate) struct Decoder {
    bitness: u32,
    got: Option<u64>,
}

impl Decoder {
    pub(crate) const fn new(bitness: u32, got: Option<u64>) -> Self {
        Self { bitness, got }
    }
}

impl crate::isa::Decode for Decoder {
    fn decode(&mut self, bytes: &[u8], addr: u64) -> Insn {
        decode(self.bitness, self.got, bytes, addr)
    }

    fn reset(&mut self) {}

    fn call(&mut self) {}

    fn starts_frame(&self, bytes: &[u8]) -> bool {
        starts_frame(self.bitness, bytes)
    }

    fn pc_thunk(&self, bytes: &[u8], _call: u64, next: u64) -> Option<Note> {
        let reg = pc_thunk(bytes).filter(|_| self.bitness == 32)?;
        Some(Note::Address { reg, addr: next })
    }

    fn argument(&self, n: usize) -> Option<u32> {
        argument(n).filter(|_| self.bitness == 64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(bitness: u32, bytes: &[u8], addr: u64) -> Insn {
        decode(bitness, Some(0x5000), bytes, addr)
    }

    #[test]
    fn control_flow() {
        let at = 0x1000;
        assert_eq!(one(64, &[0xe8, 0x0b, 0, 0, 0], at).flow, Flow::Call(0x1010));
        assert_eq!(one(64, &[0xeb, 0xfe], at).flow, Flow::Jump(0x1000));
        assert_eq!(one(64, &[0x74, 0x02], at).flow, Flow::Branch(0x1004));
        assert_eq!(one(64, &[0xc3], at).flow, Flow::Return);
        assert_eq!(one(64, &[0xcc], at).flow, Flow::Stop);
        assert_eq!(one(64, &[0xf4], at).flow, Flow::Stop);
        assert_eq!(one(64, &[0x0f, 0x0b], at).flow, Flow::Stop); // ud2
        assert_eq!(one(64, &[0x0f, 0x05], at).flow, Flow::Next); // syscall
        assert_eq!(one(64, &[0xff, 0xd0], at).flow, Flow::CallIndirect); // call rax
        assert_eq!(
            one(64, &[0xff, 0xe0], at).flow,
            Flow::JumpRegister(register_id(Register::RAX))
        ); // jmp rax
        assert_eq!(one(64, &[0x48, 0x89, 0xc8], at).flow, Flow::Next); // mov rax, rcx
        assert_eq!(one(64, &[0x06], at).flow, Flow::Invalid); // in 64-bit mode
    }

    #[test]
    fn slots() {
        // call [rip + 0x10] at 0x1000, 6 bytes long.
        assert_eq!(
            one(64, &[0xff, 0x15, 0x10, 0, 0, 0], 0x1000).flow,
            Flow::CallSlot(0x1016)
        );
        // jmp [0x402000]
        assert_eq!(
            one(32, &[0xff, 0x25, 0x00, 0x20, 0x40, 0x00], 0x1000).flow,
            Flow::JumpSlot(0x40_2000)
        );
        // jmp [ebx + 0xc], with the GOT at 0x5000.
        assert_eq!(
            one(32, &[0xff, 0xa3, 0x0c, 0, 0, 0], 0x1000).flow,
            Flow::JumpSlot(0x500c)
        );
    }

    #[test]
    fn tables_and_bounds() {
        let id = register_id;
        let (eax, ecx, r10) = (id(Register::EAX), id(Register::ECX), id(Register::R10));
        let mem = |base, index, scale, disp| Mem {
            base,
            index,
            scale,
            disp,
        };
        // jmp [eax * 4 + 0x401000]
        assert_eq!(
            one(32, &[0xff, 0x24, 0x85, 0x00, 0x10, 0x40, 0x00], 0x1000).flow,
            Flow::JumpMemory(mem(None, Some(eax), 4, 0x40_1000))
        );
        // cmp eax, 5
        assert_eq!(
            one(32, &[0x83, 0xf8, 0x05], 0x1000).note,
            Note::Compare { reg: eax, imm: 5 }
        );
        // movzx eax, byte [eax + 0x401200]
        assert_eq!(
            one(32, &[0x0f, 0xb6, 0x80, 0x00, 0x12, 0x40, 0x00], 0x1000).note,
            Note::Load {
                reg: eax,
                mem: mem(Some(eax), None, 1, 0x40_1200),
                size: 1,
                signed: false
            }
        );
        // MSVC's x64 table jump: offsets from the image base, at 0x180042726.
        let at = 0x1_8004_2726;
        // lea r10, [rip - 0x42727d] = the image base
        assert_eq!(
            one(64, &[0x4c, 0x8d, 0x15, 0xd3, 0xd8, 0xfb, 0xff], at).note,
            Note::Address {
                reg: r10,
                addr: 0x1_8000_0000
            }
        );
        // mov ecx, dword [r10 + rax*4 + 0x4289c]
        assert_eq!(
            one(64, &[0x41, 0x8b, 0x8c, 0x82, 0x9c, 0x28, 0x04, 0x00], at).note,
            Note::Load {
                reg: ecx,
                mem: mem(Some(r10), Some(eax), 4, 0x4_289c),
                size: 4,
                signed: false
            }
        );
        // add rcx, r10; jmp rcx
        assert_eq!(
            one(64, &[0x49, 0x03, 0xca], at).note,
            Note::Add {
                reg: ecx,
                base: ecx,
                index: r10,
                shift: 0,
                extend: Extend::None
            }
        );
        let jump = one(64, &[0xff, 0xe1], at);
        assert_eq!(
            (jump.flow, jump.note),
            (Flow::JumpRegister(ecx), Note::None)
        );
        // mov edi, edi; test eax, eax; sub eax, 9
        let edi = id(Register::EDI);
        assert_eq!(
            one(64, &[0x89, 0xff], at).note,
            Note::Copy { reg: edi, src: edi }
        );
        assert_eq!(one(64, &[0x85, 0xc0], at).note, Note::None);
        assert_eq!(one(64, &[0x83, 0xe8, 0x09], at).note, Note::Write(eax));
    }

    /// The two ways 32-bit position-independent code finds its own address.
    #[test]
    fn program_counter() {
        let ebx = register_id(Register::EBX);
        // __x86.get_pc_thunk.bx: mov ebx, [esp]; ret
        assert_eq!(pc_thunk(&[0x8b, 0x1c, 0x24, 0xc3]), Some(ebx));
        assert_eq!(pc_thunk(&[0x8b, 0x1c, 0x24, 0x90]), None);
        // call +0 at 0x1000; pop ebx; add ebx, 0x1234
        let call = one(32, &[0xe8, 0, 0, 0, 0], 0x1000);
        assert_eq!((call.flow, call.note), (Flow::Next, Note::Push(0x1005)));
        assert_eq!(one(32, &[0x5b], 0x1005).note, Note::Pop(ebx));
        assert_eq!(
            one(32, &[0x81, 0xc3, 0x34, 0x12, 0, 0], 0x1006).note,
            Note::Offset {
                reg: ebx,
                src: ebx,
                imm: 0x1234
            }
        );
        // push 0x8048400 (main, to __libc_start_main)
        assert_eq!(
            one(32, &[0x68, 0x00, 0x84, 0x04, 0x08], 0x1000).note,
            Note::Push(0x804_8400)
        );
        // add eax, 1 in 64-bit code truncates.
        assert_eq!(
            one(64, &[0x83, 0xc0, 0x01], 0x1000).note,
            Note::Write(register_id(Register::EAX))
        );
    }

    #[test]
    fn frames() {
        assert!(starts_frame(32, &[0x55, 0x8b, 0xec, 0x83]));
        assert!(starts_frame(32, &[0x8b, 0xff, 0x55, 0x8b, 0xec]));
        assert!(starts_frame(
            64,
            &[0xf3, 0x0f, 0x1e, 0xfa, 0x55, 0x48, 0x89, 0xe5]
        ));
        assert!(!starts_frame(64, &[0x55, 0x8b, 0xec]));
        assert!(!starts_frame(32, &[0x8b, 0xff, 0xc3]));
        assert!(!starts_frame(32, &[]));
    }

    /// Every general register has its own bit in a note's mask, below 64.
    #[test]
    fn registers_are_numbered_by_encoding() {
        // mov r8d..r15d, 1
        let mut seen = 0_u64;
        for (n, opcode) in (8..16).zip(0xb8_u8..) {
            let note = one(64, &[0x41, opcode, 1, 0, 0, 0], 0).note;
            assert_eq!(note, Note::Address { reg: n, addr: 1 });
            seen |= note.writes();
        }
        assert_eq!(seen, 0xff00);
        assert_eq!(register_id(Register::AH), 0);
        assert_eq!(register_id(Register::R15W), 15);
        // movaps xmm0, xmm1 writes no general register.
        assert_eq!(one(64, &[0x0f, 0x28, 0xc1], 0).note, Note::None);
        assert_eq!(register_id(Register::XMM31), OTHER);
    }

    #[test]
    fn padding() {
        assert!(one(64, &[0xf3, 0x0f, 0x1e, 0xfa], 0).pad); // endbr64
        assert!(one(64, &[0x90], 0).pad);
        assert!(!one(64, &[0xc3], 0).pad);
    }
}
