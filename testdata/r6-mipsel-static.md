# r6-mipsel-static

A statically linked, stripped little-endian MIPS32 Release 6 executable (musl). Release 6 reuses opcodes for compact branches, jumps and calls with no delay slot (`beqzc`, `bnezc`, `bnec`, `beqzalc`, `bltuc`, `jrc`, `jalrc`), and writes `jr` as `jalr $zero`; `e_flags` says so (`EF_MIPS_ARCH` 9). `pick`'s `switch` is a jump table bounded by a compact branch.

- Source: `r6.c` below, built by `zig cc` 0.16.0 (from the `ziglang` PyPI package): `zig cc -target mipsel-linux-musleabi -mcpu=mips32r6 -O2 -fno-inline -static -s r6.c -o r6-mipsel-static`
- SHA-256: `aa694ff4c8f54c78f0c4c8343b336c170ebd5f7603d1a878ce4cc42369c9deeb`
- Size: 23960 bytes (4658 compressed)
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
    default: return 0;
    }
}
int (*volatile hook)(unsigned, int) = pick;
int main(int argc, char **argv) {
    (void)argv;
    puts("r6");
    return hook((unsigned)argc, argc) + check(argc);
}
```

`r6-mipsel-static.rizin.json.zst` holds what rizin 0.8.2 found (`funktion-ab --save`);
`r6-mipsel-static.golden` holds what funktion finds (`FUNKTION_BLESS=1 cargo test --test fixtures`).
