# calls-sparc.o

An ELF relocatable object: 32-bit SPARC; calls are `R_SPARC_WPLT30`, and the GOT is found with `call .+8`. Four functions (`entry`, `other`, and the static `check` and `twice`) call each other and three undefined functions (`puts`, `abort`, `helper`). Unlinked, every call reads as a call to itself; linked, each reaches its callee or an import slot. Rizin 0.8.2 does not link calls in these objects, so the claims are binform's own.

- Source: `calls.c` below, built by `zig cc` 0.16.0 (from the `ziglang` PyPI package): `zig cc -target sparc-linux-gnu -O2 -fno-inline -c calls.c`
- SHA-256: `d683d6440ed21333b0f167c81e7d7872266520fa796a4ce553f216ecea9b2d19`
- Size: 3128 bytes (1343 compressed)
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

`calls-sparc.o.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`calls-sparc.o.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test fixtures`).
