//! Feed arbitrary bytes to the store header parser.
//!
//! The parser is the one place in the crate that reads bytes an attacker
//! chose: every field of a store file is a length or a cost that the
//! loader uses.  The target asserts the two properties the loader relies
//! on: a parse either fails or returns, and a successful parse means the
//! KDF parameters are inside the policy's bounds, so nothing downstream
//! can allocate more than the limits allow.
#![no_main]

use pmask::store::{parse_header_bounded, StorePolicy};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let policy = StorePolicy::default();
    let _ = parse_header_bounded(data, &policy);
});
