//! Hand-assembled call sites: the few instructions that build an argument,
//! and what [`calls`](super::calls) recovers from them.

#![allow(clippy::panic, clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used)]

use super::{Target, Value, calls};
use crate::{Arch, Binary, Functions, Origin, Seed, Segment};

/// A32 words, little-endian, concatenated into a code segment.
fn code(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
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
        seeds: vec![Seed { addr: base, origin: Origin::Entry }],
        slots: Vec::new(),
        handlers: Vec::new(),
        extents: Vec::new(),
        got: None,
        rebased: Vec::new(),
    }
}

/// Kimwolf's `connect(fd, &sockaddr, 16)`, built field by field on the stack
/// before an `svc`. The sockaddr decodes to `AF_INET`, port 8082,
/// `45.139.197.87`. rizin's `/as` misses the syscall (its number is built with
/// `mov`+`add`) and never reports arguments.
#[test]
fn arm_connect_sockaddr_from_the_stack() {
    let base = 0x1000;
    let bytes = code(&[
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
    ]);

    let bin = image(Arch::Arm, base, bytes);
    // Recovery would find this function; the test supplies it directly so it
    // exercises only the value walk.
    let funcs = Functions {
        functions: vec![crate::Function { entry: base, size: 0x100, ..Default::default() }],
        ..Default::default()
    };

    let calls = calls(&bin, &funcs);
    let connect = calls
        .iter()
        .find(|c| c.target == Target::Syscall(283))
        .unwrap_or_else(|| panic!("no connect syscall in {calls:#?}"));
    assert_eq!(bin.syscall(283), Some("connect"));

    assert_sockaddr(&connect.args[1]);
    assert_eq!(connect.args[2], Value::Int(16));
}

/// The same `connect(fd, &sockaddr, 16)` on AArch64: `movz`/`movk` build the
/// fields, `str` writes them to the stack, `x8` holds 203 (connect).
#[test]
fn arm64_connect_sockaddr_from_the_stack() {
    let base = 0x1000;
    let bytes = code(&[
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
    ]);
    let bin = image(Arch::Arm64, base, bytes);
    let funcs = Functions {
        functions: vec![crate::Function { entry: base, size: 0x100, ..Default::default() }],
        ..Default::default()
    };

    let calls = calls(&bin, &funcs);
    let connect = calls
        .iter()
        .find(|c| c.target == Target::Syscall(203))
        .unwrap_or_else(|| panic!("no connect syscall in {calls:#?}"));
    assert_eq!(bin.syscall(203), Some("connect"));
    assert_sockaddr(&connect.args[1]);
    assert_eq!(connect.args[2], Value::Int(16));
}

/// x86-64 `connect` where the sockaddr is built in an `rbp` frame, its address
/// spilled to another stack slot, then reloaded into `rsi` just before the
/// `syscall` — the shape glibc-linked code takes. Recovering it needs the
/// `rbp`-relative frame and the symbolic spill, not just `rsp` stores.
#[test]
fn x86_64_connect_sockaddr_spilled_and_reloaded() {
    let base = 0x1000;
    #[rustfmt::skip]
    let bytes = vec![
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
    ];
    let bin = image(Arch::X86_64, base, bytes);
    let funcs = Functions {
        functions: vec![crate::Function { entry: base, size: 0x100, ..Default::default() }],
        ..Default::default()
    };

    let calls = calls(&bin, &funcs);
    let connect = calls
        .iter()
        .find(|c| c.target == Target::Syscall(42))
        .unwrap_or_else(|| panic!("no connect syscall in {calls:#?}"));
    assert_eq!(bin.syscall(42), Some("connect"));
    assert_sockaddr(&connect.args[1]);
    assert_eq!(connect.args[2], Value::Int(16));
}

/// Only `svc #0` is a Linux syscall. A `cond 1111` word with a non-zero
/// comment is data (or an old-ABI form), not a syscall — this is what keeps
/// data in a recovered region from reading as millions of syscalls.
#[test]
fn arm_svc_requires_a_zero_comment() {
    let base = 0x1000;
    let bytes = code(&[
        0xe3a07001, // mov   r7, #1          ; number = exit
        0xef123456, // svc   #0x123456       ; non-zero comment: NOT a syscall
        0xef000000, // svc   #0              ; the real one
        0xe12fff1e, // bx    lr
    ]);
    let bin = image(Arch::Arm, base, bytes);
    let funcs = Functions {
        functions: vec![crate::Function { entry: base, size: 0x10, ..Default::default() }],
        ..Default::default()
    };
    let syscalls: Vec<_> =
        calls(&bin, &funcs).into_iter().filter(|c| matches!(c.target, Target::Syscall(_))).collect();
    assert_eq!(syscalls.len(), 1, "only svc #0 counts: {syscalls:#?}");
    assert_eq!(syscalls[0].target, Target::Syscall(1));
    assert_eq!(syscalls[0].addr, base + 8, "the svc #0 at offset 8");
}

/// The pointer argument decodes to `AF_INET`, port 8082, `45.139.197.87`.
fn assert_sockaddr(arg: &Value) {
    let Value::Mem { addr, bytes } = arg else {
        panic!("arg not a pointer: {arg:#?}");
    };
    assert_eq!(*addr, None, "a stack pointer");
    let known: Vec<u8> = bytes.iter().map(|b| b.expect("sockaddr byte")).collect();
    assert_eq!(
        &known[..8],
        &[0x02, 0x00, 0x1f, 0x92, 0x2d, 0x8b, 0xc5, 0x57],
        "AF_INET, port 8082, 45.139.197.87",
    );
}
