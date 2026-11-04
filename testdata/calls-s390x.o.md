# calls-s390x.o

An ELF relocatable object: s390x; calls are `brasl` with `R_390_PLT32DBL`. Four functions (`entry`, `other`, and the static `check` and `twice`) call each other and three undefined functions (`puts`, `abort`, `helper`). Unlinked, every call reads as a call to itself; linked, each reaches its callee or an import slot. Rizin 0.8.2 does not link calls in these objects, so the claims are binform's own.

- Source: `calls.c` below, built by `zig cc` 0.16.0 (from the `ziglang` PyPI package): `zig cc -target s390x-linux-gnu -O2 -fno-inline -c calls.c`
- SHA-256: `66ac91d9ed67ead4a49582d0110c26e16dd7d15b1e959de126dc6f5816814759`
- Size: 4872 bytes (1438 compressed)
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

`calls-s390x.o.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`calls-s390x.o.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test fixtures`).
