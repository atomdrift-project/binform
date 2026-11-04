//! Function recovery and call tracking over whatever parses, under the
//! quick limits: no panic, bounded time.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Ok(bin) = binform::parse(data) else {
        return;
    };
    let recovery = binform::recover(&bin, &binform::Limits::QUICK);
    let _ = binform::calls(&bin, &recovery);
});
