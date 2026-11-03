# la64-pie

A stripped, statically linked position-independent 64-bit LoongArch executable (musl). `pick`'s jump table of offsets is addressed PC-relative (`ori a2, zero, 19; bltu a2, a0, default; slli.d a0, a0, 2; pcalau12i a2, ...; addi.d a2, a2, ...; ldx.w a0, a2, a0; add.d a0, a2, a0; jr a0`), calls beyond `bl`'s reach are `pcaddu18i ra, hi; jirl ra, ra, lo`, and LLVM pads between functions with `break 0`. musl's stdio callbacks (`__stdout_write`, `__stdio_seek`) are found from the `FILE` in `.data` that holds their addresses; the two jumps through its `write` pointer stay unresolved. rizin 0.8.2's analysis finds only the entry point on LoongArch.

- Source: `switch.c` below (the same as `ppc-pie`'s), built by `zig cc` 0.16.0 (from the `ziglang` PyPI package): `zig cc -target loongarch64-linux-musl -O2 -fno-inline -fPIE -static-pie -s switch.c -o la64-pie`
- SHA-256: `cfbac81f27f9e782cade239eafaee6cb8b68b12e338c17aca006225f3e54e855`
- Size: 10696 bytes (4598 compressed)
- License: public domain (written for funktion); musl is MIT-licensed

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

`la64-pie.rizin.json.zst` holds what rizin 0.8.2 found (`funktion-ab --save`);
`la64-pie.golden` holds what funktion finds (`FUNKTION_BLESS=1 cargo test --test fixtures`).
