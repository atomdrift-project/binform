# ppc64le-static

A statically linked, stripped little-endian 64-bit PowerPC executable (the ELFv2 ABI, musl). Each function that uses the TOC has a global entry that sets it from the function's own address (`addis r2, r12, ...; addi r2, r2, ...`) and a local entry eight bytes in, which calls from within the program use; funktion starts the function at the global entry, rizin at the local one. LLVM builds no jump table for `pick`'s ten cases (it wants many more on PowerPC).

- Source: `calls.c` below, built by `zig cc` 0.16.0 (from the `ziglang` PyPI package): `zig cc -target powerpc64le-linux-musl -O2 -fno-inline -static -s calls.c -o ppc64le-static`
- SHA-256: `fb079ffa5a22958bd8f18257720279d5ab4f0fd7779acab072f66b09fcef849e`
- Size: 10120 bytes (4639 compressed)
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
    puts("ppc");
    return hook((unsigned)argc, argc) + check(argc);
}
```

`ppc64le-static.rizin.json.zst` holds what rizin 0.8.2 found (`funktion-ab --save`);
`ppc64le-static.golden` holds what funktion finds (`FUNKTION_BLESS=1 cargo test --test fixtures`).
