# ppc64le-power10-pie

A stripped, statically linked position-independent little-endian 64-bit PowerPC executable (ELFv2, musl) built for Power10, whose prefixed instructions are eight bytes long: `pick`'s jump table address comes from `pla r5, .LJTI@pcrel` (`paddi r5, 0, ..., 1`; rizin decodes its second word again as a `li`), and GOT slots are read with `pld rT, sym@got@pcrel`. musl's `_dlstart_c` calls the next start-up stage through `bl 1f; .long f - .; 1: mflr r4; lwa r12, 0(r4); add r12, r12, r4; mtctr r12; mr r4, r5; ...; bctr`.

- Source: `switch.c` below, built by `zig cc` 0.16.0 (from the `ziglang` PyPI package): `zig cc -target powerpc64le-linux-musl -mcpu=pwr10 -O2 -fno-inline -fPIE -static-pie -mllvm -ppc-min-jump-table-entries=8 -s switch.c -o ppc64le-power10-pie`
- SHA-256: `92bc7333a702840f78a46806e00c1c85e738ccabcf7f294a8b0691722270f1e0`
- Size: 11632 bytes (5003 compressed)
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

`ppc64le-power10-pie.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`ppc64le-power10-pie.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test fixtures`).
