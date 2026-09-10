#![no_main]

use libfuzzer_sys::fuzz_target;
use osv_worker_protocol::Frame;

fuzz_target!(|data: &[u8]| {
    let _ = Frame::decode(data);
});
