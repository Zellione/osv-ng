#![no_main]

use libfuzzer_sys::fuzz_target;
use osv_test_support::SecretCanary;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, remaining)) = data.split_first() else {
        return;
    };
    let marker_length = usize::from(selector) % (remaining.len().min(63) + 1);
    let (marker, artifact) = remaining.split_at(marker_length);
    let expected = !marker.is_empty()
        && artifact
            .windows(marker.len())
            .any(|window| window == marker);

    assert_eq!(SecretCanary::new(marker).occurs_in(artifact), expected);
});
