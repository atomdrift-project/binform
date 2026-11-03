# rv64-pie

A stripped, statically linked position-independent 64-bit RISC-V executable (musl, `rv64gc`: compressed instructions mixed with full-width ones). `pick`'s jump table of offsets is addressed PC-relative (`li a2, 19; bltu a2, a0, default; slli a0, a0, 2; auipc a2, ...; addi a2, a2, ...; add a0, a0, a2; lw a0, 0(a0); add a0, a0, a2; jr a0`). rizin 0.8.2's analysis finds only the entry point on RISC-V. Two jumps stay unresolved: musl's `f->write` tail calls, through a pointer. (GCC's RV64 tables zero-extend a 32-bit index first, `slli a5, s0, 32; srli s0, a5, 30`; LLVM does not, so that idiom is covered by a unit test in `src/riscv.rs` only.)

- Source: `switch.c` below (the same as `ppc-pie`'s), built by `zig cc` 0.16.0 (from the `ziglang` PyPI package): `zig cc -target riscv64-linux-musl -O2 -fno-inline -fPIE -static-pie -s switch.c -o rv64-pie`
- SHA-256: `c3420a319fb2079b90e75d00ae974d2c9f7ab11a882240033f2c5cdd5aa3e7c2`
- Size: 8464 bytes (4502 compressed)
- License: public domain (written for binform); musl is MIT-licensed

```c
extern int puts(const char *);
extern void abort(void);
static __attribute__((noinline)) int twice(int x) { return x * 2 + 1; }
static __attribute__((noinline)) int check(int x) { if (x < 0) abort(); return twice(x) + 1; }
__attribute__((noinline)) int pick(unsigned op, int x) {
    switch (op) {
    case 0: return x + 1;
    case 1: return x * 3;
    case 2: return twice(x);
    case 3: return check(x);
    case 4: return x - 7;
    case 5: return x ^ 0x55;
    case 6: return x << 3;
    case 7: return -x;
    case 8: return x / 5;
    case 9: return x % 11;
    case 10: return x | 0x100;
    case 11: return x & 0xff;
    case 12: return x * x;
    case 13: return twice(x) + check(x);
    case 14: return x >> 2;
    case 15: return x + 99;
    case 16: return x - 1234;
    case 17: return ~x;
    case 18: return x * 17;
    case 19: return check(x) * 3;
    default: return 0;
    }
}
int (*volatile hook)(unsigned, int) = pick;
int main(int argc, char **argv) {
    (void)argv;
    puts("ppc");
    return hook((unsigned)argc, argc) + check(argc);
}
```

`rv64-pie.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`rv64-pie.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test --test fixtures`).
