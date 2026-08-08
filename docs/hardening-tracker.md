# Elite hardening tracker

Baseline: `main` at `80b8b20da3171509bccbde00ab021bb5b1f7c2dc`, audited 2026-08-08.

This tracker uses the audit finding IDs as stable identifiers and links each finding to its GitHub issue. Assignment records implementation ownership only and does not satisfy independent-review gates.

## Release-blocking findings

| Finding | Reproducer/evidence plan | Dependency | Status | Owner |
| --- | --- | --- | --- | --- |
| [SQ-P0-001](https://github.com/davidtorcivia/SteadQ/issues/52) | Malicious ticket component corpus plus syscall trace proving no out-of-root open | A-001/A-002 | Implemented: [#80](https://github.com/davidtorcivia/SteadQ/pull/80) blocks root escape; A-002 removes authority-bearing paths and recomputes locations from identity; pending review and merge | @davidtorcivia |
| [SQ-P0-002](https://github.com/davidtorcivia/SteadQ/issues/53) | Mutate operation and every identity field for each ticket/resolver row | A-002 | Implemented: tickets bind queue, operation, phase, source identity, envelope digest, and payload length; pending review and merge | @davidtorcivia |
| [SQ-P0-003](https://github.com/davidtorcivia/SteadQ/issues/54) | Source/destination/both/neither/conflict and second-crash matrix | A-003, A-009 | Open | @davidtorcivia |
| [SQ-P0-004](https://github.com/davidtorcivia/SteadQ/issues/55) | Random readdir order, every budget boundary, faults, and reopen property | A-006 | Open | @davidtorcivia |
| [SQ-P0-005](https://github.com/davidtorcivia/SteadQ/issues/56) | Clock/watermark syscall fault matrix and rollback property | A-004 | Open | @davidtorcivia |
| [SQ-P0-006](https://github.com/davidtorcivia/SteadQ/issues/57) | Corrupt payload through every ack/compaction/receipt consumer | A-005 | Open | @davidtorcivia |
| [SQ-P0-007](https://github.com/davidtorcivia/SteadQ/issues/58) | Generated fault at every mutation phase; no flattened post-linearization result | A-008 | Open | @davidtorcivia |
| [SQ-P0-008](https://github.com/davidtorcivia/SteadQ/issues/59) | Deliberate barrier/token/generation model mutations and checked invariant list | A-007, A-013 | Open | @davidtorcivia |

## Priority-one findings

| Finding | Work package | Status |
| --- | --- | --- |
| [SQ-P1-001 Public raw structs](https://github.com/davidtorcivia/SteadQ/issues/61) | A-010 | Open |
| [SQ-P1-002 Incomplete typed layout](https://github.com/davidtorcivia/SteadQ/issues/62) | A-009/A-010 | Open |
| [SQ-P1-003 Verification witness](https://github.com/davidtorcivia/SteadQ/issues/63) | A-011 | Open |
| [SQ-P1-004 Bounds and conversions](https://github.com/davidtorcivia/SteadQ/issues/64) | A-009/A-010 | Open |
| [SQ-P1-005 Lossy directory names](https://github.com/davidtorcivia/SteadQ/issues/65) | A-009 | Open |
| [SQ-P1-006 Raw-FD ownership](https://github.com/davidtorcivia/SteadQ/issues/66) | A-009 | Open |
| [SQ-P1-007 Init/open protocol](https://github.com/davidtorcivia/SteadQ/issues/67) | A-008 | Open |
| [SQ-P1-008 Incomplete fsck namespace accounting](https://github.com/davidtorcivia/SteadQ/issues/68) | A-012 | Open |
| [SQ-P1-009 Inconsistent compact receipt validation](https://github.com/davidtorcivia/SteadQ/issues/69) | A-005 | Open |
| [SQ-P1-010 Destructive maintenance TOCTOU](https://github.com/davidtorcivia/SteadQ/issues/70) | A-008/A-012 | Open |
| [SQ-P1-011 String-flattened errors](https://github.com/davidtorcivia/SteadQ/issues/71) | A-008/A-017/A-018 | Open |
| [SQ-P1-012 Critical mutation exclusions](https://github.com/davidtorcivia/SteadQ/issues/72) | A-019 | Open |
| [SQ-P1-013 Self-referential testkit](https://github.com/davidtorcivia/SteadQ/issues/73) | A-014 | Open |
| [SQ-P1-014 Missing stateful fuzzing](https://github.com/davidtorcivia/SteadQ/issues/74) | A-014/A-019 | Open |
| [SQ-P1-015 Incomplete C ABI](https://github.com/davidtorcivia/SteadQ/issues/75) | A-018 | Open |
| [SQ-P1-016 CLI bypasses core safety](https://github.com/davidtorcivia/SteadQ/issues/76) | A-017 | Open |
| [SQ-P1-017 Streaming inefficiency/ambiguity](https://github.com/davidtorcivia/SteadQ/issues/77) | A-011/A-016 | Open |
| [SQ-P1-018 Missing target/toolchain/version policy](https://github.com/davidtorcivia/SteadQ/issues/78) | A-000 | Complete in #51: release/certification target is x86_64-unknown-linux-gnu; the compile guard admits its sanitizer-target cfg family; other target configurations fail compilation |

## Freeze blockers

- No filesystem profile is certified.
- Independent Rust, Linux-filesystem, formal-methods, and adversarial-operator reviewers are unassigned.
