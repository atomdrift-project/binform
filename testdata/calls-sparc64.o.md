# calls-sparc64.o

An ELF relocatable object: SPARC V9; calls are `R_SPARC_WPLT30`. Four functions (`entry`, `other`, and the static `check` and `twice`) call each other and three undefined functions (`puts`, `abort`, `helper`). Unlinked, every call reads as a call to itself; linked, each reaches its callee or an import slot. Rizin 0.8.2 does not link calls in these objects, so the claims are binform's own.

- Source: `calls.c` below, built by `zig cc` 0.16.0 (from the `ziglang` PyPI package): `zig cc -target sparc64-linux-gnu -O2 -fno-inline -c calls.c`
- SHA-256: `f5a1a82940e17ac72756c5e93634b9d34d6603058abd20af4344a645298202dc`
- Size: 4560 bytes (1412 compressed)
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

`calls-sparc64.o.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`calls-sparc64.o.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test fixtures`).
