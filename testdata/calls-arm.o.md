# calls-arm.o

An ELF relocatable object: A32; calls are `R_ARM_CALL`, REL with the addend in place. Four functions (`entry`, `other`, and the static `check` and `twice`) call each other and three undefined functions (`puts`, `abort`, `helper`). Unlinked, every call reads as a call to itself; linked, each reaches its callee or an import slot. Rizin 0.8.2 does not link calls in these objects, so the claims are binform's own.

- Source: `calls.c` below, built by `zig cc` 0.16.0 (from the `ziglang` PyPI package): `zig cc -target arm-linux-gnueabihf -O2 -fno-inline -c calls.c`
- SHA-256: `9a7274b1251eb010ba6a66e5b15490652b0a1a2d72fd6add95d64f8ebf3a329b`
- Size: 3884 bytes (1616 compressed)
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

`calls-arm.o.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`calls-arm.o.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test --test fixtures`).
