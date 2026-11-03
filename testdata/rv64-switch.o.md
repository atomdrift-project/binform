# rv64-switch.o

An ELF relocatable object: 64-bit RISC-V, position-independent, built for linker relaxation. `pick`'s jump table is addressed `auipc; addi` (`R_RISCV_PCREL_HI20`, then `R_RISCV_PCREL_LO12_I` naming the `auipc`), and its entries are label differences (`R_RISCV_ADD32`/`R_RISCV_SUB32` pairs) that read as zero until applied. `hook`'s address comes from the GOT (`R_RISCV_GOT_HI20`). Rizin 0.8.2 applies none of the branch relocations: its `pick` branches to itself.

- Source: `switch.c` below (the same as `ppc-pie`'s), built by `zig cc` 0.16.0 (from the `ziglang` PyPI package): `zig cc -target riscv64-linux-musl -O2 -fno-inline -fPIC -mrelax -c switch.c -o rv64-switch.o`
- SHA-256: `dac2975113ce3617e278b562919197a7cd4a7c7f7d513b1399d9a739f3e6c7a6`
- Size: 17128 bytes (3259 compressed)
- License: public domain (written for binform)

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

`rv64-switch.o.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`rv64-switch.o.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test --test fixtures`).
