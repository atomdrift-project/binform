# calls-loongarch64.o

An ELF relocatable object: 64-bit LoongArch, position-independent, built for linker relaxation: calls are `pcaddu18i ra; jirl ra, ra` pairs (`R_LARCH_CALL36`), branches within `.text` are relocated (`R_LARCH_B16`, `R_LARCH_B26`), and `ALIGN` relocations mark the `nop`s that start it. Four functions (`entry`, `other`, and the static `check` and `twice`) call each other and three undefined functions (`puts`, `abort`, `helper`). Unlinked, every call reads as a call to itself; linked, each reaches its callee or an import slot. Rizin 0.8.2 does not link calls in these objects, so the claims are binform's own.

- Source: `calls.c` below (the same as `calls-mips.o`'s), built by `zig cc` 0.16.0 (from the `ziglang` PyPI package): `zig cc -target loongarch64-linux-musl -O2 -fno-inline -fPIC -mrelax -c calls.c -o calls-loongarch64.o`
- SHA-256: `158d6da7a995c6098444f5d30c5dc5957fc21c6ea7b7f8df862ed9dfa465e969`
- Size: 8640 bytes (1809 compressed)
- License: public domain (written for binform)

```c
extern int puts(const char *);
extern void abort(void);
extern int helper(int);
static __attribute__((noinline)) int twice(int x) { return helper(x) * 2; }
static __attribute__((noinline)) int check(int x) { if (x < 0) abort(); return twice(x) + 1; }
int entry(int x) { puts("hi"); return check(x) + twice(x + 1); }
int other(int x) { return entry(x) - check(x); }
```

`calls-loongarch64.o.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`calls-loongarch64.o.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test fixtures`).
