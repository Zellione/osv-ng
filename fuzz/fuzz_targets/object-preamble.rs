#![no_main]

use libfuzzer_sys::fuzz_target;
use osv_storage::ObjectPreamble;

fuzz_target!(|data: &[u8]| {
    // Parsing is fixed-size, allocation-free, and performs no cryptographic work.
    let _ = ObjectPreamble::parse(data);
});
