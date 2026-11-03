# ppc-pie

A stripped, statically linked position-independent 32-bit big-endian PowerPC executable (musl). Each function that needs the GOT finds it from its own address (`bcl 20, 31, $+4; mflr r30; addis r30, r30, ...; addi r30, r30, ...`), and `pick`'s jump table of offsets is found through a GOT slot (`lwz r5, -0x8000(r30); slwi r3, r3, 2; lwzx r3, r5, r3; add r3, r5, r3; mtctr r3; bctr`) that holds zero in the file until its `R_PPC_RELATIVE` relocation fills it. musl's start code jumps over a word of data with `bl` (`bl 1f; .long _DYNAMIC - .; 1: mflr r4`).

- Source: `switch.c` below, built by `zig cc` 0.16.0 (from the `ziglang` PyPI package): `zig cc -target powerpc-linux-musleabihf -O2 -fno-inline -fPIE -static-pie -mllvm -ppc-min-jump-table-entries=8 -s switch.c -o ppc-pie` (LLVM builds jump tables on PowerPC only for many more cases by default)
- SHA-256: `547b2fa9d1ef711e9575134fcd21283388c32d89403193f8acef068f90c15a25`
- Size: 10236 bytes (4779 compressed)
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

`ppc-pie.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`ppc-pie.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test --test fixtures`).
