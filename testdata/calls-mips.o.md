# calls-mips.o

An ELF relocatable object: big-endian MIPS32, position-independent: calls go through `$t9`, and `R_MIPS_JALR` names each callee. Four functions (`entry`, `other`, and the static `check` and `twice`) call each other and three undefined functions (`puts`, `abort`, `helper`). Unlinked, every call reads as a call to itself; linked, each reaches its callee or an import slot. Rizin 0.8.2 does not link calls in these objects, so the claims are binform's own.

- Source: `calls.c` below, built by `zig cc` 0.16.0 (from the `ziglang` PyPI package): `zig cc -target mips-linux-gnueabi -O2 -fno-inline -c calls.c`
- SHA-256: `6f99ee446508898e85bae4032a763c6b4329512e849e1e5f47f6e3ff0cd4523b`
- Size: 4508 bytes (1759 compressed)
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

`calls-mips.o.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`calls-mips.o.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test fixtures`).
