//! Hand-assembled images, one per idiom funktion once missed: each test
//! holds the few instructions that make the idiom and checks what recovery
//! makes of them.

// A test fails by panicking.
#![allow(clippy::panic, clippy::indexing_slicing)]

use funktion::{Arch, Found, Function, Handler, Image, Import, Origin, RefKind, Seed, Segment};

fn segment(addr: u64, bytes: &[u8], executable: bool) -> Segment<'_> {
    Segment {
        addr,
        bytes: bytes.into(),
        executable,
    }
}

fn entry(addr: u64) -> Seed {
    Seed {
        addr,
        origin: Origin::Entry,
    }
}

fn image(arch: Arch, segments: Vec<Segment<'_>>, seeds: Vec<Seed>) -> Image<'_> {
    Image {
        arch,
        segments,
        seeds,
        imports: Vec::new(),
        handlers: Vec::new(),
        extents: Vec::new(),
        got: None,
        rebased: Vec::new(),
    }
}

fn function(functions: &[Function], entry: u64) -> &Function {
    functions
        .iter()
        .find(|function| function.entry == entry)
        .unwrap_or_else(|| panic!("no function at {entry:#x}"))
}

fn cases(function: &Function) -> Vec<u64> {
    function
        .refs
        .iter()
        .filter(|r| r.kind == RefKind::Case)
        .map(|r| r.to)
        .collect()
}

/// Bytes at `addr` within code that starts at `base`, filled with `fill`.
fn place(code: &mut Vec<u8>, base: u64, addr: u64, bytes: &[u8], fill: u8) {
    let at = usize::try_from(addr - base).unwrap_or(usize::MAX);
    if code.len() < at + bytes.len() {
        code.resize(at + bytes.len(), fill);
    }
    code[at..at + bytes.len()].copy_from_slice(bytes);
}

fn words(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

/// 32-bit position-independent code finds its GOT from the address a PC
/// thunk returns, and its jump table at a GOT-relative offset whose entries
/// are GOT-relative too.
#[test]
fn i386_pic_jump_table() {
    let mut code = Vec::new();
    let mut at = |addr, bytes: &[u8]| place(&mut code, 0x1000, addr, bytes, 0x90);
    at(0x1000, &[0xe8, 0x3b, 0, 0, 0]); // call 0x1040 (the thunk)
    at(0x1005, &[0x81, 0xc3, 0xfb, 0x1f, 0, 0]); // add ebx, 0x1ffb: the GOT, 0x3000
    at(0x100b, &[0x83, 0xf8, 0x02]); // cmp eax, 2
    at(0x100e, &[0x77, 0x20]); // ja 0x1030
    at(0x1010, &[0x8b, 0x94, 0x83, 0x00, 0xff, 0xff, 0xff]); // mov edx, [ebx + eax*4 - 0x100]
    at(0x1017, &[0x01, 0xda]); // add edx, ebx
    at(0x1019, &[0xff, 0xe2]); // jmp edx
    for case in [0x1020, 0x1024, 0x1028, 0x1030] {
        at(case, &[0xc3]); // ret
    }
    at(0x1040, &[0x8b, 0x1c, 0x24, 0xc3]); // mov ebx, [esp]; ret
    let table: Vec<u8> = [0x1020_u32, 0x1024, 0x1028]
        .iter()
        .flat_map(|target| target.wrapping_sub(0x3000).to_le_bytes())
        .collect();
    let image = image(
        Arch::X86,
        vec![segment(0x1000, &code, true), segment(0x2f00, &table, false)],
        vec![entry(0x1000)],
    );
    let recovery = funktion::recover(&image);
    let switch = function(&recovery.functions, 0x1000);
    assert_eq!(cases(switch), [0x1020, 0x1024, 0x1028]);
    assert_eq!(switch.blocks, 6);
    assert!(
        function(&recovery.functions, 0x1040)
            .found
            .contains(Found::CALL)
    );
}

/// Clang's form: a call to the next instruction, and a pop.
#[test]
fn i386_call_next_is_not_a_function() {
    let mut code = Vec::new();
    let mut at = |addr, bytes: &[u8]| place(&mut code, 0x1000, addr, bytes, 0x90);
    at(0x1000, &[0xe8, 0, 0, 0, 0]); // call 0x1005
    at(0x1005, &[0x5b]); // pop ebx
    at(0x1006, &[0x81, 0xc3, 0xfb, 0x1f, 0, 0]); // add ebx, 0x1ffb: 0x3000
    at(0x100c, &[0x83, 0xf8, 0x01]); // cmp eax, 1
    at(0x100f, &[0x77, 0x1f]); // ja 0x1030
    at(0x1011, &[0x8b, 0x94, 0x83, 0x00, 0xff, 0xff, 0xff]); // mov edx, [ebx + eax*4 - 0x100]
    at(0x1018, &[0x01, 0xda]); // add edx, ebx
    at(0x101a, &[0xff, 0xe2]); // jmp edx
    for case in [0x1020, 0x1024, 0x1030] {
        at(case, &[0xc3]);
    }
    let table: Vec<u8> = [0x1020_u32, 0x1024]
        .iter()
        .flat_map(|target| target.wrapping_sub(0x3000).to_le_bytes())
        .collect();
    let image = image(
        Arch::X86,
        vec![segment(0x1000, &code, true), segment(0x2f00, &table, false)],
        vec![entry(0x1000)],
    );
    let recovery = funktion::recover(&image);
    assert_eq!(
        recovery
            .functions
            .iter()
            .map(|f| f.entry)
            .collect::<Vec<_>>(),
        [0x1000]
    );
    assert_eq!(cases(&recovery.functions[0]), [0x1020, 0x1024]);
}

/// GCC's A64 sparse switch: signed byte entries, scaled by four and added
/// to an anchor inside the function.
#[test]
fn a64_byte_table() {
    let code = words(&[
        0x7100_081f, // 0x10000 cmp w0, #2
        0x5400_01e8, // 0x10004 b.hi 0x10040
        0x9000_0081, // 0x10008 adrp x1, 0x20000
        0x9100_0021, // 0x1000c add x1, x1, #0
        0x3860_4821, // 0x10010 ldrb w1, [x1, w0, uxtw]
        0x1000_0082, // 0x10014 adr x2, 0x10024
        0x8b21_8841, // 0x10018 add x1, x2, w1, sxtb #2
        0xd61f_0020, // 0x1001c br x1
        0xd65f_03c0, // 0x10020 ret
        0xd65f_03c0, // 0x10024 ret
        0xd65f_03c0, // 0x10028 ret
        0xd420_0000, // brk #0
        0xd420_0000,
        0xd420_0000,
        0xd420_0000,
        0xd420_0000,
        0xd65f_03c0, // 0x10040 ret
    ]);
    let table = [0xff, 0x00, 0x01]; // -1, 0, 1 words from the anchor
    let image = image(
        Arch::Arm64,
        vec![
            segment(0x1_0000, &code, true),
            segment(0x2_0000, &table, false),
        ],
        vec![entry(0x1_0000)],
    );
    let recovery = funktion::recover(&image);
    let switch = function(&recovery.functions, 0x1_0000);
    assert_eq!(cases(switch), [0x1_0020, 0x1_0024, 0x1_0028]);
    assert_eq!(switch.blocks, 6);
}

/// Go's A64 switch: a bounded index into absolute addresses.
#[test]
fn a64_absolute_table() {
    let code = words(&[
        0xf100_041f, // 0x10000 cmp x0, #1
        0x5400_0108, // 0x10004 b.hi 0x10024
        0x9000_0081, // 0x10008 adrp x1, 0x20000
        0x9100_0021, // 0x1000c add x1, x1, #0
        0xf860_7821, // 0x10010 ldr x1, [x1, x0, lsl #3]
        0xd61f_0020, // 0x10014 br x1
        0xd65f_03c0, // 0x10018 ret
        0xd65f_03c0, // 0x1001c ret
        0xd420_0000, // 0x10020 brk #0
        0xd65f_03c0, // 0x10024 ret
    ]);
    let table: Vec<u8> = [0x1_0018_u64, 0x1_001c]
        .iter()
        .flat_map(|target| target.to_le_bytes())
        .collect();
    let image = image(
        Arch::Arm64,
        vec![
            segment(0x1_0000, &code, true),
            segment(0x2_0000, &table, false),
        ],
        vec![entry(0x1_0000)],
    );
    let recovery = funktion::recover(&image);
    assert_eq!(
        cases(function(&recovery.functions, 0x1_0000)),
        [0x1_0018, 0x1_001c]
    );
}

/// `_start` passes `main` to the C runtime, which calls it: nothing in the
/// binary does, so only the argument finds it once symbols are stripped.
#[test]
fn main_from_libc_start_main() {
    let mut x64 = Vec::new();
    let mut at = |addr, bytes: &[u8]| place(&mut x64, 0x1000, addr, bytes, 0xcc);
    at(0x1000, &[0x48, 0xc7, 0xc7, 0x00, 0x11, 0, 0]); // mov rdi, 0x1100
    at(0x1007, &[0xff, 0x15, 0xf3, 0x1f, 0, 0]); // call [rip + 0x1ff3]: the slot at 0x3000
    at(0x100d, &[0xf4]); // hlt
    at(0x1100, &[0x31, 0xc0, 0xc3]); // main: xor eax, eax; ret

    let mut x86 = Vec::new();
    let mut at = |addr, bytes: &[u8]| place(&mut x86, 0x1000, addr, bytes, 0xcc);
    at(0x1000, &[0x68, 0x00, 0x11, 0, 0]); // push 0x1100
    at(0x1005, &[0xff, 0x15, 0x00, 0x30, 0, 0]); // call [0x3000]
    at(0x100b, &[0xf4]); // hlt
    at(0x1100, &[0x31, 0xc0, 0xc3]);

    let a64 = words(&[
        0x9000_0000, // 0x10000 adrp x0, 0x10000
        0x9104_1000, // 0x10004 add x0, x0, #0x104
        0x9400_003e, // 0x10008 bl 0x10100: __libc_start_main
        0xd420_0000, // brk #0
    ]);
    let mut a64 = a64;
    a64.resize(0x100, 0);
    a64.extend(words(&[0xd65f_03c0, 0xd65f_03c0])); // 0x10100 and main at 0x10104
    let a64_main = 0x1_0104;

    let slot = vec![0_u8; 8];
    for (arch, code, base, main) in [
        (Arch::X86_64, &x64[..], 0x1000, 0x1100),
        (Arch::X86, &x86[..], 0x1000, 0x1100),
        (Arch::Arm64, &a64[..], 0x1_0000, a64_main),
    ] {
        let mut image = image(
            arch,
            vec![segment(base, code, true), segment(0x3000, &slot, false)],
            vec![entry(base)],
        );
        image.imports.push(Import {
            slot: 0x3000,
            name: "__libc_start_main".into(),
        });
        if arch == Arch::Arm64 {
            // Called directly, by name.
            image.seeds.push(Seed {
                addr: 0x1_0100,
                origin: Origin::Symbol("__libc_start_main".into()),
            });
        }
        let recovery = funktion::recover(&image);
        let found = recovery
            .functions
            .iter()
            .find(|f| f.entry == main)
            .map(|f| f.found);
        assert!(
            found.is_some_and(|found| found.contains(Found::MAIN)),
            "{arch:?}: main at {main:#x} found {found:?}"
        );
    }
}

/// A landing pad is part of its function though nothing branches to it.
#[test]
fn landing_pads_are_explored() {
    let mut code = Vec::new();
    let mut at = |addr, bytes: &[u8]| place(&mut code, 0x1000, addr, bytes, 0xcc);
    at(0x1000, &[0xe8, 0xfb, 0x00, 0, 0]); // call 0x1100
    at(0x1005, &[0xc3]); // ret
    at(0x1010, &[0x48, 0x89, 0xc7]); // pad: mov rdi, rax
    at(0x1013, &[0xe8, 0xf8, 0x00, 0, 0]); // call 0x1110 (_Unwind_Resume)
    at(0x1018, &[0xcc]);
    at(0x1100, &[0xc3]);
    at(0x1110, &[0xc3]);
    let mut image = image(
        Arch::X86_64,
        vec![segment(0x1000, &code, true)],
        vec![entry(0x1000)],
    );
    let without = funktion::recover(&image);
    image.handlers.push(Handler {
        function: 0x1000,
        addr: 0x1010,
    });
    let with = funktion::recover(&image);
    assert_eq!(function(&without.functions, 0x1000).blocks, 1);
    let thrower = function(&with.functions, 0x1000);
    assert_eq!(thrower.blocks, 2);
    assert!(thrower.refs.iter().any(|r| r.to == 0x1110));
    // The pad's callee is found, and the pad is no function of its own.
    assert!(with.functions.iter().any(|f| f.entry == 0x1110));
    assert!(!with.functions.iter().any(|f| f.entry == 0x1010));
}

/// A shrink-wrapped function's parts each have an unwind entry; code that
/// runs straight into the next part continues the function. A part that is
/// called, or that code reaches only by returning from a call, stays a
/// function.
#[test]
fn unwind_parts_join_the_function_that_runs_into_them() {
    let unwind = |addr| Seed {
        addr,
        origin: Origin::Unwind,
    };
    let mut code = Vec::new();
    let mut at = |addr, bytes: &[u8]| place(&mut code, 0x1000, addr, bytes, 0xcc);
    at(0x1000, &[0x48, 0x85, 0xff]); // test rdi, rdi
    at(0x1003, &[0x74, 0x02]); // je 0x1007, seen before the part is joined
    at(0x1005, &[0x31, 0xc0]); // xor eax, eax: runs into 0x1007
    at(0x1007, &[0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3]); // the part with the frame
    at(0x1020, &[0xe8, 0x0b, 0, 0, 0]); // call 0x1030, which may not return
    at(0x1025, &[0xc3]); // a function of its own
    at(0x1030, &[0xc3]);
    at(0x1040, &[0xe8, 0xeb, 0xff, 0xff, 0xff]); // call 0x1030
    at(0x1045, &[0x0f, 0x1f, 0x00]); // nop dword [rax]: padding, not a way in
    at(0x1048, &[0xc3]); // a function of its own
    let seeds = vec![
        unwind(0x1000),
        unwind(0x1007),
        unwind(0x1020),
        unwind(0x1025),
        unwind(0x1040),
        unwind(0x1048),
    ];
    let image = image(Arch::X86_64, vec![segment(0x1000, &code, true)], seeds);
    let recovery = funktion::recover(&image);
    let entries: Vec<u64> = recovery.functions.iter().map(|f| f.entry).collect();
    assert_eq!(entries, [0x1000, 0x1020, 0x1025, 0x1030, 0x1040, 0x1048]);
    let joined = function(&recovery.functions, 0x1000);
    assert_eq!((joined.blocks, joined.complexity), (3, 2));
}

/// Stripped and static, the start routine has no name: the entry point's
/// call just before a trap is the hand-off.
#[test]
fn main_from_an_unnamed_start_routine() {
    let mut code = Vec::new();
    let mut at = |addr, bytes: &[u8]| place(&mut code, 0x1000, addr, bytes, 0xcc);
    at(0x1000, &[0x48, 0xc7, 0xc7, 0x00, 0x11, 0, 0]); // mov rdi, 0x1100
    at(0x1007, &[0xe8, 0x04, 0x01, 0, 0]); // call 0x1110, the start routine
    at(0x100c, &[0xf4]); // hlt
    at(0x1100, &[0x31, 0xc0, 0xc3]); // main
    at(0x1110, &[0xff, 0xd7, 0xc3]); // call rdi; ret
    // Without the trap it is an ordinary call.
    let mut plain = code.clone();
    plain[0xc] = 0xc3;
    for (code, found) in [(&code, true), (&plain, false)] {
        let image = image(
            Arch::X86_64,
            vec![segment(0x1000, code, true)],
            vec![entry(0x1000)],
        );
        let recovery = funktion::recover(&image);
        let main = recovery.functions.iter().find(|f| f.entry == 0x1100);
        assert_eq!(main.is_some_and(|f| f.found.contains(Found::MAIN)), found);
    }
}

/// LLVM's A64 switch on an enum whose range it knows: a byte table with no
/// bound before it. The cases are unknown, but the unwind table says how
/// far the function runs, and its unreached code is the cases.
#[test]
fn unbounded_table_cases_lie_in_the_extent() {
    let code = words(&[
        0x7940_0008, // 0x10000 ldrh w8, [x0]
        0x9000_0089, // 0x10004 adrp x9, 0x20000
        0x9100_0129, // 0x10008 add x9, x9, #0
        0x1000_008a, // 0x1000c adr x10, 0x1001c
        0x3868_692b, // 0x10010 ldrb w11, [x9, x8]
        0x8b0b_094a, // 0x10014 add x10, x10, x11, lsl #2
        0xd61f_0140, // 0x10018 br x10
        0x5280_0020, // 0x1001c mov w0, #1
        0xd65f_03c0, // 0x10020 ret
        0xd503_201f, // 0x10024 nop
        0x5280_0040, // 0x10028 mov w0, #2
        0xd65f_03c0, // 0x1002c ret
        0x5280_0060, // 0x10030 mov w0, #3: past the function
        0xd65f_03c0, // 0x10034 ret
    ]);
    let table = [0, 3];
    let segments = || {
        vec![
            segment(0x1_0000, &code, true),
            segment(0x2_0000, &table, false),
        ]
    };

    let alone = funktion::recover(&image(Arch::Arm64, segments(), vec![entry(0x1_0000)]));
    assert_eq!(alone.unresolved, 1);
    assert_eq!(function(&alone.functions, 0x1_0000).blocks, 1);

    let mut spanned = image(Arch::Arm64, segments(), vec![entry(0x1_0000)]);
    spanned.extents.push(0x1_0000..0x1_0030);
    let recovery = funktion::recover(&spanned);
    assert_eq!(recovery.functions.len(), 1);
    let switch = function(&recovery.functions, 0x1_0000);
    assert_eq!((switch.blocks, switch.size), (3, 0x30));
    assert_eq!(recovery.covered, 0x2c, "the nop is no case");
}

/// What a caller weighs before trusting a recovery: code no function
/// covers, and paths into bytes that do not decode.
#[test]
fn weak_recovery_says_so() {
    let mut code = vec![0x90, 0x90, 0x06]; // nop; nop; invalid in 64-bit mode
    code.resize(0x100, 0);
    let recovery = funktion::recover(&image(
        Arch::X86_64,
        vec![segment(0x1000, &code, true)],
        vec![entry(0x1000)],
    ));
    assert_eq!((recovery.code, recovery.covered), (0x100, 2));
    assert_eq!(recovery.invalid, 1);
    assert_eq!(recovery.unresolved, 0);
}

fn halves(halves: &[u16]) -> Vec<u8> {
    halves.iter().flat_map(|half| half.to_le_bytes()).collect()
}

fn big_words(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_be_bytes()).collect()
}

/// Thumb code keeps its mode in bit 0: a Thumb entry, a `bl` to Thumb and a
/// `blx` to A32. A return inside an `it` block is conditional: the code
/// after it is the same function.
#[test]
fn thumb_and_a32_interwork() {
    let mut code = halves(&[
        0xb510, // 0x8000: push {r4, lr}
        0xf000, 0xf807, // 0x8002: bl 0x8014 (Thumb)
        0x2800, // 0x8006: cmp r0, #0
        0xbf08, // 0x8008: it eq
        0xbd10, // 0x800a: popeq {r4, pc}
        0xf000, 0xe808, // 0x800c: blx 0x8020 (A32)
        0xbd10, // 0x8010: pop {r4, pc}
        0xbf00, // 0x8012: nop
        0x4770, // 0x8014: bx lr
        0xbf00, 0xbf00, 0xbf00, 0xbf00, 0xbf00, // padding to 0x8020
    ]);
    code.extend(words(&[0xe12f_ff1e])); // 0x8020: bx lr
    let image = image(
        Arch::Arm,
        vec![segment(0x8000, &code, true)],
        vec![entry(0x8001)],
    );
    let recovery = funktion::recover(&image);
    let entries: Vec<u64> = recovery.functions.iter().map(|f| f.entry).collect();
    assert_eq!(entries, [0x8001, 0x8015, 0x8020]);
    let main = function(&recovery.functions, 0x8001);
    assert_eq!((main.blocks, main.size), (2, 0x12));
}

/// GCC's Thumb-2 switch: `tbb` reads a byte of halfwords to skip from the
/// table that follows it, after a `cmp` and a branch to the default case.
#[test]
fn thumb_tbb_table() {
    let code = halves(&[
        0x2b02, // 0x8000: cmp r3, #2
        0xd805, // 0x8002: bhi 0x8010
        0xe8df, 0xf003, // 0x8004: tbb [pc, r3]
        0x0302, 0x0004, // 0x8008: the table: 2, 3, 4 halfwords on
        0x4770, // 0x800c: bx lr
        0x4770, // 0x800e: bx lr
        0x4770, // 0x8010: bx lr
    ]);
    let image = image(
        Arch::Arm,
        vec![segment(0x8000, &code, true)],
        vec![entry(0x8001)],
    );
    let recovery = funktion::recover(&image);
    let switch = function(&recovery.functions, 0x8001);
    assert_eq!(cases(switch), [0x800d, 0x800f, 0x8011]);
    assert_eq!(switch.blocks, 5);
    assert_eq!(recovery.unresolved, 0);
}

/// GCC's A32 switches: `addls pc, pc, rN, lsl #2` into a run of branches,
/// and `ldrls pc, [pc, rN, lsl #2]` from a table of addresses, each after a
/// `cmp` and followed by the branch to the default case.
#[test]
fn a32_tables() {
    let code = words(&[
        0xe353_0002, // 0x10000: cmp r3, #2
        0x908f_f103, // 0x10004: addls pc, pc, r3, lsl #2
        0xea00_0002, // 0x10008: b 0x10018
        0xe12f_ff1e, // 0x1000c: bx lr
        0xe12f_ff1e, // 0x10010: bx lr
        0xe12f_ff1e, // 0x10014: bx lr
        0xe12f_ff1e, // 0x10018: bx lr
        0xe353_0001, // 0x1001c: cmp r3, #1
        0x979f_f103, // 0x10020: ldrls pc, [pc, r3, lsl #2]
        0xea00_0001, // 0x10024: b 0x10030
        0x0001_0034, // 0x10028: the table
        0x0001_0038, // 0x1002c
        0xe12f_ff1e, // 0x10030: bx lr
        0xe12f_ff1e, // 0x10034: bx lr
        0xe12f_ff1e, // 0x10038: bx lr
    ]);
    let image = image(
        Arch::Arm,
        vec![segment(0x1_0000, &code, true)],
        vec![entry(0x1_0000), entry(0x1_001c)],
    );
    let recovery = funktion::recover(&image);
    let branches = function(&recovery.functions, 0x1_0000);
    assert_eq!(cases(branches), [0x1_000c, 0x1_0010, 0x1_0014]);
    let addresses = function(&recovery.functions, 0x1_001c);
    assert_eq!(cases(addresses), [0x1_0034, 0x1_0038]);
    assert_eq!(recovery.unresolved, 0);
}

/// SPARC: a call and its delay slot are one instruction, so the call
/// returns past the slot; `ret; restore` and `retl; nop` return.
#[test]
fn sparc_delay_slots() {
    let code = big_words(&[
        0x9de3_bfa0, // 0x1000: save %sp, -96, %sp
        0x4000_0008, // 0x1004: call 0x1024
        0x0100_0000, // 0x1008: nop (slot)
        0x80a2_2000, // 0x100c: cmp %o0, 0
        0x0280_0003, // 0x1010: be 0x101c
        0x0100_0000, // 0x1014: nop (slot)
        0xb010_2001, // 0x1018: mov 1, %i0
        0x81c7_e008, // 0x101c: ret
        0x81e8_0000, // 0x1020: restore (slot)
        0x81c3_e008, // 0x1024: retl
        0x0100_0000, // 0x1028: nop (slot)
    ]);
    let image = image(
        Arch::Sparc,
        vec![segment(0x1000, &code, true)],
        vec![entry(0x1000)],
    );
    let recovery = funktion::recover(&image);
    let main = function(&recovery.functions, 0x1000);
    assert_eq!((main.blocks, main.size), (3, 0x24));
    assert!(
        main.refs
            .iter()
            .any(|r| r.kind == RefKind::Call && r.to == 0x1024)
    );
    assert_eq!(function(&recovery.functions, 0x1024).size, 8);
}

/// SuperH: `bsr` and `rts` take a delay slot, `bt` does not.
#[test]
fn superh_delay_slots() {
    let code = halves(&[
        0x4f22, // 0x1000: sts.l pr, @-r15
        0xb007, // 0x1002: bsr 0x1014
        0x0009, // 0x1004: nop (slot)
        0x2008, // 0x1006: tst r0, r0
        0x8900, // 0x1008: bt 0x100c
        0x7001, // 0x100a: add #1, r0
        0x4f26, // 0x100c: lds.l @r15+, pr
        0x000b, // 0x100e: rts
        0x0009, // 0x1010: nop (slot)
        0x0009, // 0x1012: nop
        0x000b, // 0x1014: rts
        0x0009, // 0x1016: nop (slot)
    ]);
    let image = image(
        Arch::SuperH,
        vec![segment(0x1000, &code, true)],
        vec![entry(0x1000)],
    );
    let recovery = funktion::recover(&image);
    let main = function(&recovery.functions, 0x1000);
    assert_eq!((main.blocks, main.size), (3, 0x12));
    assert_eq!(function(&recovery.functions, 0x1014).size, 4);
}
