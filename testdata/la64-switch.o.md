# la64-switch.o

An ELF relocatable object: 64-bit LoongArch, position-independent, built for linker relaxation. `pick`'s jump table is addressed `pcalau12i; addi.d` (`R_LARCH_PCALA_HI20`, `R_LARCH_PCALA_LO12`), and its entries are `R_LARCH_32_PCREL` offsets that read as zero until applied. `hook`'s address comes from the GOT (`R_LARCH_GOT_PC_HI20`, `R_LARCH_GOT_PC_LO12`).

- Source: `switch.c` below (the same as `ppc-pie`'s), built by `zig cc` 0.16.0 (from the `ziglang` PyPI package): `zig cc -target loongarch64-linux-musl -O2 -fno-inline -fPIC -mrelax -c switch.c -o la64-switch.o`
- SHA-256: `a2cfc36d9321a53cebce4301230cc0a122d87be55d139fdb1746992b600aac11`
- Size: 12936 bytes (2661 compressed)
- License: public domain (written for funktion)

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

`la64-switch.o.rizin.json.zst` holds what rizin 0.8.2 found (`funktion-ab --save`);
`la64-switch.o.golden` holds what funktion finds (`FUNKTION_BLESS=1 cargo test --test fixtures`).
