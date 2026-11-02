# calls-mips-static.o

An ELF relocatable object: big-endian MIPS32, not position-independent: calls are `jal` with `R_MIPS_26`. Four functions (`entry`, `other`, and the static `check` and `twice`) call each other and three undefined functions (`puts`, `abort`, `helper`). Unlinked, every call reads as a call to itself; linked, each reaches its callee or an import slot. Rizin 0.8.2 does not link calls in these objects, so the claims are funktion's own.

- Source: `calls.c` below, built by `zig cc` 0.16.0 (from the `ziglang` PyPI package): `zig cc -target mips-freestanding -O2 -fno-inline -c calls.c`
- SHA-256: `a1d2f0e19b8446af0146df5812e50ade0aad946423e9334cd060b6c70efefbda`
- Size: 4316 bytes (1708 compressed)
- License: public domain (written for funktion)

```c
extern int puts(const char *);
extern void abort(void);
extern int helper(int);
static __attribute__((noinline)) int twice(int x) { return helper(x) * 2; }
static __attribute__((noinline)) int check(int x) { if (x < 0) abort(); return twice(x) + 1; }
int entry(int x) { puts("hi"); return check(x) + twice(x + 1); }
int other(int x) { return entry(x) - check(x); }
```

`calls-mips-static.o.rizin.json.zst` holds what rizin 0.8.2 found (`funktion-ab --save`);
`calls-mips-static.o.golden` holds what funktion finds (`FUNKTION_BLESS=1 cargo test --test fixtures`).
