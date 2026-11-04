//! Hand-assembled call sites: the few instructions that build an argument,
//! and what [`calls`](super::calls) recovers from them; then a call and a
//! syscall in real binaries from the fixture corpus.

#![allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used
)]

use super::{Call, Target, Value, calls};
use crate::{
    Arch, Binary, Dest, Function, Import, Origin, Recovery, Ref, RefKind, Seed, Segment, Slot,
};

/// 32-bit words, little-endian, concatenated into a code segment.
fn code(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

/// Thumb halfwords, little-endian, concatenated into a code segment.
fn thumb(halves: &[u16]) -> Vec<u8> {
    halves.iter().flat_map(|h| h.to_le_bytes()).collect()
}

fn image(arch: Arch, base: u64, bytes: Vec<u8>) -> Binary<'static> {
    Binary {
        format: crate::Format::Elf,
        arch: Some(arch),
        entry: Some(base),
        sections: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        segments: vec![Segment {
            addr: base,
            bytes: bytes.into(),
            executable: true,
        }],
        seeds: vec![Seed {
            addr: base,
            origin: Origin::Entry,
        }],
        slots: Vec::new(),
        handlers: Vec::new(),
        extents: Vec::new(),
        got: None,
        rebased: Vec::new(),
    }
}

/// One function at `entry`, `size` bytes, with `refs`: what recovery would
/// find, supplied directly so a test exercises only the value walk.
fn one(entry: u64, size: u64, refs: Vec<Ref>) -> Recovery {
    Recovery {
        functions: vec![Function {
            entry,
            size,
            refs,
            ..Default::default()
        }],
        ..Default::default()
    }
}

/// The calls of a single function of `size` bytes at the image's base (in
/// Thumb, `entry` carries bit 0).
fn walk(arch: Arch, base: u64, entry: u64, bytes: Vec<u8>) -> (Binary<'static>, Vec<Call>) {
    let bin = image(arch, base, bytes);
    let calls = calls(&bin, &one(entry, 0x100, Vec::new()));
    (bin, calls)
}

/// The only syscall in `calls`.
fn syscall(calls: &[Call]) -> &Call {
    let mut syscalls = calls
        .iter()
        .filter(|c| matches!(c.target, Target::Syscall(_)));
    let found = syscalls
        .next()
        .unwrap_or_else(|| panic!("no syscall in {calls:#?}"));
    assert!(
        syscalls.next().is_none(),
        "more than one syscall in {calls:#?}"
    );
    found
}

/// A stack pointer argument's known bytes.
fn stack_bytes(arg: &Value) -> &[Option<u8>] {
    match arg {
        Value::Mem { addr: None, bytes } => bytes,
        _ => panic!("not a stack pointer: {arg:#?}"),
    }
}

/// The pointer argument decodes to `AF_INET`, port 8082, `45.139.197.87`.
fn assert_sockaddr(arg: &Value) {
    let known: Vec<u8> = stack_bytes(arg)
        .iter()
        .map(|b| b.expect("sockaddr byte"))
        .collect();
    assert_eq!(
        &known[..8],
        &[0x02, 0x00, 0x1f, 0x92, 0x2d, 0x8b, 0xc5, 0x57],
        "AF_INET, port 8082, 45.139.197.87",
    );
}

/// Kimwolf's `connect(fd, &sockaddr, 16)`, built field by field on the stack
/// before an `svc`, its number built with `mov` and `add`.
#[test]
fn arm_connect_sockaddr_from_the_stack() {
    let (bin, calls) = walk(
        Arch::Arm,
        0x1000,
        0x1000,
        code(&[
            0xe24dd010, // sub   sp, sp, #16
            0xe3a06000, // mov   r6, #0
            0xe58d6000, // str   r6, [sp]
            0xe58d6004, // str   r6, [sp, #4]
            0xe58d6008, // str   r6, [sp, #8]
            0xe58d600c, // str   r6, [sp, #12]
            0xe3a00002, // mov   r0, #2
            0xe1cd00b0, // strh  r0, [sp]            ; sin_family = AF_INET
            0xe3010f92, // movw  r0, #0x1f92
            0xe6bf0fb0, // rev16 r0, r0              ; port to network order
            0xe1cd00b2, // strh  r0, [sp, #2]        ; sin_port = 8082 (big-endian)
            0xe3a0002d, // mov   r0, #0x2d           ; 45
            0xe5cd0004, // strb  r0, [sp, #4]
            0xe3a0008b, // mov   r0, #0x8b           ; 139
            0xe5cd0005, // strb  r0, [sp, #5]
            0xe3a000c5, // mov   r0, #0xc5           ; 197
            0xe5cd0006, // strb  r0, [sp, #6]
            0xe3a00057, // mov   r0, #0x57           ; 87
            0xe5cd0007, // strb  r0, [sp, #7]
            0xe1a0100d, // mov   r1, sp              ; &sockaddr
            0xe3a02010, // mov   r2, #16
            0xe3a07c01, // mov   r7, #0x100
            0xe287701b, // add   r7, r7, #0x1b       ; 283 = connect
            0xef000000, // svc   #0
            0xe12fff1e, // bx    lr
        ]),
    );
    let connect = syscall(&calls);
    assert_eq!(connect.target, Target::Syscall(Some(283)));
    assert_eq!(bin.syscall(283), Some("connect"));
    assert_sockaddr(&connect.args[1]);
    assert_eq!(connect.args[2], Value::Int(16));
}

/// The same `connect(fd, &sockaddr, 16)` on AArch64: `movz`/`movk` build the
/// fields, `str` writes them to the stack, `x8` holds 203 (connect).
#[test]
fn arm64_connect_sockaddr_from_the_stack() {
    let (bin, calls) = walk(
        Arch::Arm64,
        0x1000,
        0x1000,
        code(&[
            0xd10043ff, // sub   sp, sp, #16
            0x52800040, // mov   w0, #2
            0x790003e0, // strh  w0, [sp]              ; sin_family
            0x529243e1, // mov   w1, #0x921f
            0x790007e1, // strh  w1, [sp, #2]          ; sin_port = 8082 (big-endian)
            0x529165a2, // mov   w2, #0x8b2d
            0x72aaf8a2, // movk  w2, #0x57c5, lsl #16  ; 45.139.197.87
            0xb90007e2, // str   w2, [sp, #4]
            0x910003e1, // mov   x1, sp                ; &sockaddr
            0xd2800202, // mov   x2, #16
            0xd2801968, // mov   x8, #203              ; connect
            0xd4000001, // svc   #0
            0xd65f03c0, // ret
        ]),
    );
    let connect = syscall(&calls);
    assert_eq!(connect.target, Target::Syscall(Some(203)));
    assert_eq!(bin.syscall(203), Some("connect"));
    assert_sockaddr(&connect.args[1]);
    assert_eq!(connect.args[2], Value::Int(16));
}

/// x86-64 `connect` where the sockaddr is built in an `rbp` frame, its address
/// spilled to another stack slot, then reloaded into `rsi` just before the
/// `syscall`, as glibc-linked code does.
#[test]
fn x86_64_connect_sockaddr_spilled_and_reloaded() {
    #[rustfmt::skip]
    let (bin, calls) = walk(Arch::X86_64, 0x1000, 0x1000, vec![
        0x55,                               // push rbp
        0x48, 0x89, 0xe5,                   // mov  rbp, rsp
        0x48, 0x81, 0xec, 0x80, 0, 0, 0,    // sub  rsp, 0x80
        0x66, 0xc7, 0x45, 0xe0, 0x02, 0x00, // mov  word [rbp-0x20], 2      ; AF_INET
        0x66, 0xc7, 0x45, 0xe2, 0x1f, 0x92, // mov  word [rbp-0x1e], 0x921f ; port 8082 BE
        0xc7, 0x45, 0xe4, 0x2d, 0x8b, 0xc5, 0x57, // mov dword [rbp-0x1c], ...; 45.139.197.87
        0x48, 0x8d, 0x45, 0xe0,             // lea  rax, [rbp-0x20]         ; &sockaddr
        0x48, 0x89, 0x45, 0xc0,             // mov  [rbp-0x40], rax         ; spill the pointer
        0x48, 0x8b, 0x75, 0xc0,             // mov  rsi, [rbp-0x40]         ; reload it
        0xba, 0x10, 0x00, 0x00, 0x00,       // mov  edx, 16
        0xb8, 0x2a, 0x00, 0x00, 0x00,       // mov  eax, 42                 ; connect
        0x0f, 0x05,                         // syscall
        0xc3,                               // ret
    ]);
    let connect = syscall(&calls);
    assert_eq!(connect.target, Target::Syscall(Some(42)));
    assert_eq!(bin.syscall(42), Some("connect"));
    assert_sockaddr(&connect.args[1]);
    assert_eq!(connect.args[2], Value::Int(16));
}

/// 32-bit x86 `int 0x80`: `write(1, buf, 4)` with the buffer in an `ebp`
/// frame below the saved `ebp`, at a negative displacement.
#[test]
fn x86_int_0x80_reads_registers_and_frame() {
    #[rustfmt::skip]
    let (bin, calls) = walk(Arch::X86, 0x1000, 0x1000, vec![
        0x55,                               // push ebp
        0x89, 0xe5,                         // mov  ebp, esp
        0x83, 0xec, 0x10,                   // sub  esp, 16
        0xc7, 0x45, 0xf0, b'A', b'B', b'C', b'D', // mov dword [ebp-0x10], "ABCD"
        0x8d, 0x4d, 0xf0,                   // lea  ecx, [ebp-0x10]
        0xbb, 0x01, 0x00, 0x00, 0x00,       // mov  ebx, 1
        0xba, 0x04, 0x00, 0x00, 0x00,       // mov  edx, 4
        0xb8, 0x04, 0x00, 0x00, 0x00,       // mov  eax, 4                  ; write
        0xcd, 0x80,                         // int  0x80
        0xc3,                               // ret
    ]);
    let write = syscall(&calls);
    assert_eq!(write.target, Target::Syscall(Some(4)));
    assert_eq!(bin.syscall(4), Some("write"));
    assert_eq!(write.args[0], Value::Int(1));
    assert_eq!(stack_bytes(&write.args[1]), b"ABCD".map(Some));
    assert_eq!(write.args[2], Value::Int(4));
}

/// `push` and `pop` move the stack pointer: `[rsp+n]` after a push is the
/// slot `[rsp+n-8]` before it, and a pop reads back what was pushed.
#[test]
fn x86_64_push_and_pop_move_the_stack_pointer() {
    #[rustfmt::skip]
    let (_, calls) = walk(Arch::X86_64, 0x1000, 0x1000, vec![
        0x48, 0x83, 0xec, 0x10,             // sub  rsp, 16
        0xc7, 0x44, 0x24, 0x08, 42, 0, 0, 0, // mov dword [rsp+8], 42
        0x6a, 0x07,                         // push 7
        0x8b, 0x74, 0x24, 0x10,             // mov  esi, [rsp+0x10]         ; the 42
        0x58,                               // pop  rax                     ; the 7
        0x48, 0x89, 0xc7,                   // mov  rdi, rax
        0xb8, 0x3c, 0x00, 0x00, 0x00,       // mov  eax, 60
        0x0f, 0x05,                         // syscall
        0xc3,                               // ret
    ]);
    let exit = syscall(&calls);
    assert_eq!(exit.args[..2], [Value::Int(7), Value::Int(42)]);
}

/// A small constant is an integer even where an image based at zero maps it.
#[test]
fn small_constants_are_integers() {
    #[rustfmt::skip]
    let (_, calls) = walk(Arch::X86_64, 0, 0, vec![
        0xba, 0x10, 0x00, 0x00, 0x00,       // mov  edx, 16
        0xb8, 0x2a, 0x00, 0x00, 0x00,       // mov  eax, 42
        0x0f, 0x05,                         // syscall
        0xc3,                               // ret
    ]);
    assert_eq!(syscall(&calls).args[2], Value::Int(16));
}

/// Only `svc #0` is a Linux syscall: a non-zero comment is another ABI's, and
/// only clobbers r0.
#[test]
fn arm_svc_requires_a_zero_comment() {
    let (_, calls) = walk(
        Arch::Arm,
        0x1000,
        0x1000,
        code(&[
            0xe3a07001, // mov   r7, #1          ; number = exit
            0xef123456, // svc   #0x123456       ; not a Linux syscall
            0xef000000, // svc   #0              ; the real one
            0xe12fff1e, // bx    lr
        ]),
    );
    let exit = syscall(&calls);
    assert_eq!(exit.target, Target::Syscall(Some(1)));
    assert_eq!(exit.addr, 0x1008, "the svc #0 at offset 8");
}

/// `ldm sp!, {r4-r7}` loads r7 from a frame slot the walk does not know: the
/// number it held before is gone.
#[test]
fn arm_ldm_overwrites_its_registers() {
    let (_, calls) = walk(
        Arch::Arm,
        0x1000,
        0x1000,
        code(&[
            0xe3a07001, // mov   r7, #1
            0xe8bd00f0, // ldm   sp!, {r4-r7}
            0xef000000, // svc   #0
            0xe12fff1e, // bx    lr
        ]),
    );
    assert_eq!(syscall(&calls).target, Target::Syscall(None));
}

/// Thumb `connect(fd, &sockaddr, 16)`, the sockaddr stored through `sp` and
/// through a copy of it, its address taken with `add r1, sp, #0`.
#[test]
fn thumb_connect_sockaddr_from_the_stack() {
    let (_, calls) = walk(
        Arch::Arm,
        0x1000,
        0x1001,
        thumb(&[
            0xb084, // sub   sp, #16
            0x2002, // movs  r0, #2
            0x9000, // str   r0, [sp]
            0x201f, // movs  r0, #0x1f
            0x466b, // mov   r3, sp
            0x7098, // strb  r0, [r3, #2]
            0xa900, // add   r1, sp, #0
            0x2210, // movs  r2, #16
            0x27ff, // movs  r7, #255
            0x371c, // adds  r7, #28        ; 283 = connect
            0xdf00, // svc   #0
            0x4770, // bx    lr
        ]),
    );
    let connect = syscall(&calls);
    assert_eq!(connect.target, Target::Syscall(Some(283)));
    assert_eq!(
        stack_bytes(&connect.args[1]),
        [Some(2), Some(0), Some(0x1f), Some(0)]
    );
    assert_eq!(connect.args[2], Value::Int(16));
}

/// Thumb's usual syscall number load: `ldr r7, [pc, #n]` from the literal
/// pool after the function.
#[test]
fn thumb_syscall_number_from_a_literal() {
    let (_, calls) = walk(
        Arch::Arm,
        0x1000,
        0x1001,
        thumb(&[
            0x4f01, // ldr   r7, [pc, #4]   ; the word at 0x1008
            0x2000, // movs  r0, #0
            0xdf00, // svc   #0
            0x4770, // bx    lr
            0x011b, 0x0000, // .word 283
        ]),
    );
    assert_eq!(syscall(&calls).target, Target::Syscall(Some(283)));
}

/// `push` and `pop` of a register list: a pop restores what the push saved,
/// and a pop of a slot the walk does not know clears its registers.
#[test]
fn thumb_push_and_pop() {
    let (_, calls) = walk(
        Arch::Arm,
        0x1000,
        0x1001,
        thumb(&[
            0x2703, // movs  r7, #3
            0xb580, // push  {r7, lr}
            0x2709, // movs  r7, #9
            0xbc80, // pop   {r7}
            0xdf00, // svc   #0
            0x4770, // bx    lr
        ]),
    );
    assert_eq!(syscall(&calls).target, Target::Syscall(Some(3)));

    let (_, calls) = walk(
        Arch::Arm,
        0x1000,
        0x1001,
        thumb(&[
            0x2701, // movs  r7, #1
            0xbcf0, // pop   {r4-r7}
            0xdf00, // svc   #0
            0x4770, // bx    lr
        ]),
    );
    assert_eq!(syscall(&calls).target, Target::Syscall(None));
}

/// A Thumb-2 load writes the register in bits 15:12 of its second halfword.
#[test]
fn thumb2_load_writes_rt() {
    let (_, calls) = walk(
        Arch::Arm,
        0x1000,
        0x1001,
        thumb(&[
            0x2701, // movs  r7, #1
            0x200b, // movs  r0, #11
            0x9001, // str   r0, [sp, #4]
            0xf8dd, 0x7004, // ldr.w r7, [sp, #4]
            0xdf00, // svc   #0
            0x4770, // bx    lr
        ]),
    );
    assert_eq!(syscall(&calls).target, Target::Syscall(Some(11)));
}

/// An instruction in an `it` block may not run: what it writes is unknown.
#[test]
fn thumb_it_block_is_conditional() {
    let (_, calls) = walk(
        Arch::Arm,
        0x1000,
        0x1001,
        thumb(&[
            0x2701, // movs  r7, #1
            0x2800, // cmp   r0, #0
            0xbf08, // it    eq
            0x2702, // moveq r7, #2
            0xdf00, // svc   #0
            0x4770, // bx    lr
        ]),
    );
    assert_eq!(syscall(&calls).target, Target::Syscall(None));
}

/// `ldr` with an unsigned offset loads, and reads back the frame; `str q0`
/// stores sixteen bytes of a SIMD register, not one of `x0`.
#[test]
fn arm64_loads_and_simd_stores() {
    let (_, calls) = walk(
        Arch::Arm64,
        0x1000,
        0x1000,
        code(&[
            0xd28000a0, // mov   x0, #5
            0xf90007e0, // str   x0, [sp, #8]
            0xd28000e1, // mov   x1, #7
            0xf94007e1, // ldr   x1, [sp, #8]
            0xd2800808, // mov   x8, #64
            0xd4000001, // svc   #0
            0xd65f03c0, // ret
        ]),
    );
    assert_eq!(syscall(&calls).args[1], Value::Int(5));

    let (_, calls) = walk(
        Arch::Arm64,
        0x1000,
        0x1000,
        code(&[
            0x52800040, // mov   w0, #2
            0x790003e0, // strh  w0, [sp]
            0x3d8003e0, // str   q0, [sp]
            0x910003e1, // mov   x1, sp
            0xd2800808, // mov   x8, #64
            0xd4000001, // svc   #0
            0xd65f03c0, // ret
        ]),
    );
    let write = syscall(&calls);
    assert_eq!(write.args[0], Value::Int(2));
    assert_eq!(stack_bytes(&write.args[1]), []);
}

/// ADRP's page offset is signed: one page back.
#[test]
fn arm64_adrp_backward() {
    let (_, calls) = walk(
        Arch::Arm64,
        0x10000,
        0x10000,
        code(&[
            0xf0ffffe1, // adrp  x1, 0xf000
            0xd2800808, // mov   x8, #64
            0xd4000001, // svc   #0
            0xd65f03c0, // ret
        ]),
    );
    assert_eq!(syscall(&calls).args[1], Value::Int(0xf000));
}

/// Register 31 is the zero register as `mov`'s source and a store's data.
#[test]
fn arm64_zero_register() {
    let (_, calls) = walk(
        Arch::Arm64,
        0x1000,
        0x1000,
        code(&[
            0x52824680, // mov   w0, #0x1234
            0xb90007e0, // str   w0, [sp, #4]
            0xb90007ff, // str   wzr, [sp, #4]
            0x2a1f03e1, // mov   w1, wzr
            0x910003e2, // mov   x2, sp
            0xd2800808, // mov   x8, #64
            0xd4000001, // svc   #0
            0xd65f03c0, // ret
        ]),
    );
    let write = syscall(&calls);
    assert_eq!(write.args[1], Value::Int(0));
    assert_eq!(
        stack_bytes(&write.args[2]),
        [None, None, None, None, Some(0), Some(0), Some(0), Some(0)]
    );
}

/// A call through an import's slot, through another slot of the same
/// import, and through a stub that only jumps through the slot, each reaches
/// the import; a call through any other slot has no known target.
#[test]
fn calls_reach_imports_through_slots_and_stubs() {
    #[rustfmt::skip]
    let mut bin = image(Arch::X86_64, 0x1000, vec![
        0xff, 0x15, 0xfa, 0x1f, 0x00, 0x00, // call [rip+0x1ffa]            ; 0x3000
        0xff, 0x15, 0xfc, 0x1f, 0x00, 0x00, // call [rip+0x1ffc]            ; 0x3008
        0xe8, 0x0f, 0x00, 0x00, 0x00,       // call 0x1020                  ; the stub
        0xff, 0x15, 0xe9, 0x2f, 0x00, 0x00, // call [rip+0x2fe9]            ; 0x4000
        0xc3,                               // ret
    ]);
    bin.imports = vec![Import {
        name: "connect".into(),
        slot: Some(0x3000),
        ..Default::default()
    }];
    bin.slots = [0x3000, 0x3008]
        .map(|slot| Slot {
            slot,
            name: "connect".into(),
            import: None,
        })
        .to_vec();
    bin.index_slots();
    let mut funcs = one(0x1000, 0x18, Vec::new());
    funcs.stubs.insert(0x1020, 0x3000);
    let targets: Vec<Target> = calls(&bin, &funcs).iter().map(|c| c.target).collect();
    assert_eq!(
        targets,
        [
            Target::Import(0),
            Target::Import(0),
            Target::Import(0),
            Target::Unknown
        ]
    );
}

/// The walk resets where control may arrive from elsewhere (a branch
/// target), and does not decode what no block reaches (the bytes after a
/// return).
#[test]
fn walk_resets_at_joins_and_skips_unreached_bytes() {
    #[rustfmt::skip]
    let bin = image(Arch::X86_64, 0x1000, vec![
        0xb8, 0x2a, 0x00, 0x00, 0x00,       // mov  eax, 42
        0x0f, 0x05,                         // syscall
        0xb8, 0x2a, 0x00, 0x00, 0x00,       // mov  eax, 42
        0x0f, 0x05,                         // syscall                      ; a branch target
        0xc3,                               // ret
        0xb8, 0x3c, 0x00, 0x00, 0x00,       // mov  eax, 60                 ; unreached
        0x0f, 0x05,                         // syscall
        0xc3,                               // ret
    ]);
    let branch = Ref {
        from: 0x1010,
        to: Dest::Code(0x100c),
        kind: RefKind::Branch,
    };
    let found: Vec<(u64, Target)> = calls(&bin, &one(0x1000, 0x17, vec![branch]))
        .iter()
        .map(|c| (c.addr, c.target))
        .collect();
    assert_eq!(
        found,
        [
            (0x1005, Target::Syscall(Some(42))),
            (0x100c, Target::Syscall(None))
        ]
    );
}

/// Overlapping functions walk the same call; the record kept is the one whose
/// walk saw more of its arguments.
#[test]
fn overlapping_walks_keep_the_richest_record() {
    #[rustfmt::skip]
    let bin = image(Arch::X86_64, 0x1000, vec![
        0xbf, 0x05, 0x00, 0x00, 0x00,       // mov  edi, 5
        0xe8, 0xf6, 0x0f, 0x00, 0x00,       // call 0x2000                  ; also an entry
        0xc3,                               // ret
    ]);
    let funcs = Recovery {
        functions: vec![
            Function {
                entry: 0x1000,
                size: 11,
                ..Default::default()
            },
            Function {
                entry: 0x1005,
                size: 6,
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let found = calls(&bin, &funcs);
    assert_eq!(found.len(), 1, "{found:#?}");
    assert_eq!(found[0].target, Target::Addr(0x2000));
    assert_eq!(found[0].args, [Value::Int(5)]);
}

/// The calls of a fixture, recovered as a consumer would.
fn fixture(name: &str, check: impl Fn(&Binary<'_>, &[Call])) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join(format!("{name}.zst"));
    let compressed = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let bytes =
        zstd::decode_all(&compressed[..]).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let bin = crate::parse(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
    let funcs = crate::recover(&bin, &crate::Limits::DEFAULT);
    check(&bin, &calls(&bin, &funcs));
}

/// A static glibc executable's startup asks for its CET status:
/// `arch_prctl(ARCH_CET_STATUS, buf)`, the number and the first argument
/// constants.
#[test]
fn fixture_static_glibc_syscall() {
    fixture("apply-seccomp", |bin, calls| {
        let call = calls
            .iter()
            .find(|c| c.addr == 0x4035fe)
            .expect("the syscall");
        assert_eq!(call.target, Target::Syscall(Some(158)));
        assert_eq!(bin.syscall(158), Some("arch_prctl"));
        assert_eq!(call.args.first(), Some(&Value::Int(0x3001)));
    });
}

/// A shared library's calls through its PLT stubs reach their imports, with
/// their constant arguments: `__cxa_allocate_exception(8)`.
#[test]
fn fixture_plt_calls_reach_imports() {
    fixture("classic-level-linux-x64.node", |bin, calls| {
        let call = calls.iter().find(|c| c.addr == 0x1702c).expect("the call");
        let Target::Import(index) = call.target else {
            panic!("not an import: {call:#?}");
        };
        assert_eq!(bin.imports[index].name, "__cxa_allocate_exception");
        assert_eq!(call.args, [Value::Int(8)]);
    });
}
