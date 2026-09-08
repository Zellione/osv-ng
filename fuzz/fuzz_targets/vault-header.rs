#![no_main]

use libfuzzer_sys::fuzz_target;
use osv_crypto::VaultHeader;

fuzz_target!(|data: &[u8]| {
    // Parsing is fixed-size, allocation-free, and never invokes Argon2.
    let _ = VaultHeader::parse(data);
});
