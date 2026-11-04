# calls-mips64el.so

A little-endian MIPS64 shared library: calls load `$t9` from the GOT, whose slots `DT_MIPS_GOTSYM` names. Four functions (`entry`, `other`, and the static `check` and `twice`) call each other and three undefined functions (`puts`, `abort`, `helper`). Each call reaches its callee or an import slot; the claims are binform's own.

- Source: `calls.c` below, built by `zig cc` 0.16.0 (from the `ziglang` PyPI package): `zig cc -target mips64el-linux-gnuabi64 -O2 -fno-inline -shared calls.c -o calls-mips64el.so`
- SHA-256: `cb9641a69f6e94b1e46d30c24104f261ee0c2578b8ed556fbf612299e3bb7f8c`
- Size: 5560 bytes (1796 compressed)
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

`calls-mips64el.so.rizin.json.zst` holds what rizin 0.8.2 found (`binform-ab --save`);
`calls-mips64el.so.golden` holds what binform finds (`BINFORM_BLESS=1 cargo test fixtures`).
