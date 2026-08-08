// Fuzz target: transition-ticket schema and semantic validation.
// Property: arbitrary input cannot panic the strict ticket parser.

#![no_main]

use libfuzzer_sys::fuzz_target;
use steadq_core::TransitionTicket;

fuzz_target!(|data: &[u8]| {
    let _ = TransitionTicket::from_json(data);
});
