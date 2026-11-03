# calls-mips64.o

An ELF relocatable object: big-endian MIPS64 (RELA, with three types per relocation): calls through `$t9` with `R_MIPS_JALR`. Four functions (`entry`, `other`, and the static `check` and `twice`) call each other and three undefined functions (`puts`, `abort`, `helper`). Unlinked, every call reads as a call to itself; linked, each reaches its callee or an import slot. Rizin 0.8.2 does not link calls in these objects, so the claims are binform's own.

- Source: `calls.c` below, built by `zig cc` 0.16.0 (from the `ziglang` PyPI package): `zig cc -target mips64-linux-gnuabi64 -O2 -fno-inline -c calls.c`
- SHA-256: `00449161c9491dd3d10b3d4225ebf7c656fd59895d66caee9faeae18feb6b6d7`
- Size: 6424 bytes (1758 compressed)
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

`calls-mips64.o.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`calls-mips64.o.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test --test fixtures`).
