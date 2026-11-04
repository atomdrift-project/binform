//! Parsing any bytes returns, without panicking, in bounded time.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = binform::parse(data);
});
