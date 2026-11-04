# Security

binform is built to read untrusted binaries. Any input that makes it
panic, run without bound, or use memory out of proportion to its size is a
bug we treat as a security issue.

Report one by opening an issue, with the binform version and the input or
a way to build it. If the input is malware, attach it zstd-compressed and
say so.

Inputs that are only slow within the configured `Limits`, or that recover
wrong functions, are ordinary bugs.
