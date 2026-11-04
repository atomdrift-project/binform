# calls-mips.so

A big-endian MIPS32 shared library: calls load `$t9` from the GOT (through `$s0`, which LLVM keeps `_gp` in) and the GOT names its imports by `DT_MIPS_GOTSYM`, not by relocations. Four functions (`entry`, `other`, and the static `check` and `twice`) call each other and three undefined functions (`puts`, `abort`, `helper`). Each call reaches its callee or an import slot; the claims are binform's own.

- Source: `calls.c` below, built by `zig cc` 0.16.0 (from the `ziglang` PyPI package): `zig cc -target mips-linux-gnueabi -O2 -fno-inline -shared calls.c -o calls-mips.so`
- SHA-256: `4044a37db8cb5e327fdf9fb099692800f364c18a5e61b6ac76cb7ecc6a3ef437`
- Size: 4220 bytes (1799 compressed)
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

`calls-mips.so.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`calls-mips.so.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test fixtures`).
