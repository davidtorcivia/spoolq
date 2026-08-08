// SteadQ command-line interface.

use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// Stable exit codes per spec section 11.5
#[allow(dead_code)]
const EXIT_SUCCESS: u8 = 0;
#[allow(dead_code)]
const EXIT_ORDINARY: u8 = 1;
#[allow(dead_code)]
const EXIT_INDETERMINATE: u8 = 2;
#[allow(dead_code)]
const EXIT_CORRUPTION: u8 = 3;
#[allow(dead_code)]
const EXIT_RESOURCE_EXHAUSTED: u8 = 4;
#[allow(dead_code)]
const EXIT_PERMISSION: u8 = 5;
const EXIT_IO_FAILURE: u8 = 6;
#[allow(dead_code)]
const EXIT_UNSUPPORTED: u8 = 64;
use steadq_core::{CreateOptions, EnqueueInput, EnqueueOutcome, LeaseOutcome, OpenOptions, Queue};

#[derive(Parser)]
#[command(name = "steadq", about = "Crash-safe filesystem queue")]
struct Cli {
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new queue
    Init {
        path: PathBuf,
        #[arg(long, default_value = "64")]
        shards: u32,
        #[arg(long, default_value = "3600000000000")]
        terminal_bucket_width_ns: u64,
    },
    /// Enqueue a job
    Put {
        path: PathBuf,
        /// Input file, or - for stdin
        file: Option<String>,
        #[arg(long, default_value = "application/octet-stream")]
        content_type: String,
        #[arg(long, default_value = "3")]
        max_attempts: u32,
        #[arg(long)]
        not_before: Option<u64>,
        #[arg(long)]
        producer_id: Option<String>,
    },
    /// Lease a job
    Lease {
        path: PathBuf,
        #[arg(long, default_value = "30")]
        duration_seconds: u64,
        #[arg(long)]
        handle_file: Option<PathBuf>,
        #[arg(long)]
        ticket_out: Option<PathBuf>,
    },
    /// Stats
    Stats { path: PathBuf },
    /// Doctor: check environment
    Doctor {
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Acknowledge a lease
    Ack {
        path: PathBuf,
        #[arg(long)]
        handle_file: PathBuf,
    },
    /// Retry a lease
    Retry {
        path: PathBuf,
        #[arg(long)]
        handle_file: PathBuf,
        #[arg(long)]
        after_seconds: Option<u64>,
    },
    /// Bury a lease
    Bury {
        path: PathBuf,
        #[arg(long)]
        handle_file: PathBuf,
        #[arg(long, default_value = "0")]
        reason: u16,
    },
    /// Run a recovery pass
    Recover {
        path: PathBuf,
        #[arg(long)]
        watch: bool,
        #[arg(long, default_value = "1000")]
        budget_ops: u32,
        #[arg(long, default_value = "100")]
        budget_ms: u64,
    },
    /// Inspect a job by ID
    Inspect { path: PathBuf, job_id: String },
    /// Verify a job or receipt file
    Verify {
        file: PathBuf,
        #[arg(long)]
        deep: bool,
    },
    /// Dump format info for a file
    FormatDump { file: PathBuf },
    /// Resolve an indeterminate operation
    Resolve {
        path: PathBuf,
        #[arg(long)]
        result_file: PathBuf,
        #[arg(long)]
        stabilize: bool,
    },
    /// Run a benchmark
    Bench {
        path: PathBuf,
        #[arg(long, default_value = "1")]
        producers: u32,
        #[arg(long, default_value = "1")]
        consumers: u32,
        #[arg(long, default_value = "10")]
        duration_seconds: u64,
        #[arg(long, default_value = "1024")]
        payload_size: usize,
        #[arg(long, default_value = "30")]
        lease_duration_seconds: u64,
    },
    /// Administrative operations
    Admin {
        #[command(subcommand)]
        command: AdminCommands,
    },
}

#[derive(Subcommand)]
enum AdminCommands {
    /// List dead jobs
    DeadList { path: PathBuf },
    /// Inspect a dead job
    DeadInspect { path: PathBuf, job_id: String },
    /// Export a dead job's payload
    DeadExport {
        path: PathBuf,
        job_id: String,
        output: PathBuf,
    },
    /// Remove a dead job
    DeadRemove { path: PathBuf, job_id: String },
    /// List quarantined objects
    QuarantineList { path: PathBuf },
    /// Inspect a quarantined object
    QuarantineInspect {
        path: PathBuf,
        quarantine_id: String,
    },
    /// Export a quarantined object's raw bytes
    QuarantineExport {
        path: PathBuf,
        quarantine_id: String,
        output: PathBuf,
    },
    /// Remove a quarantined object
    QuarantineRemove {
        path: PathBuf,
        quarantine_id: String,
    },
    /// Compact receipts manually
    CompactReceipts { path: PathBuf },
}

fn parse_duration_seconds(s: u64) -> Option<u64> {
    s.checked_mul(1_000_000_000)
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init {
            path,
            shards,
            terminal_bucket_width_ns,
        } => {
            let opts = CreateOptions {
                shard_count: shards,
                terminal_bucket_width_ns,
                ..Default::default()
            };
            match Queue::init(&path, &opts) {
                Ok(format) => {
                    eprintln!("initialized queue at {}", path.display());
                    eprintln!("queue_id: {}", steadq_names::hex_encode(&format.queue_id));
                    eprintln!("shards: {}", format.shard_count);
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("init failed: {e}");
                    ExitCode::FAILURE
                }
            }
        }

        Commands::Put {
            path,
            file,
            content_type,
            max_attempts,
            not_before,
            producer_id,
        } => {
            // C-54: Fail on read error instead of silently enqueueing empty payload
            let payload = match file.as_deref() {
                Some("-") | None => {
                    use std::io::Read;
                    let mut buf = Vec::new();
                    match std::io::stdin().read_to_end(&mut buf) {
                        Ok(_) => buf,
                        Err(e) => {
                            eprintln!("stdin read failed: {e}");
                            return ExitCode::FAILURE;
                        }
                    }
                }
                Some(f) => match std::fs::read(f) {
                    Ok(data) => data,
                    Err(e) => {
                        eprintln!("file read failed: {e}");
                        return ExitCode::FAILURE;
                    }
                },
            };

            let queue = match Queue::open(&path, &OpenOptions::default()) {
                Ok(q) => q,
                Err(e) => {
                    eprintln!("open failed: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let mut queue = queue;

            let input = steadq_core::EnqueueInput {
                maximum_attempts: max_attempts,
                content_type,
                payload,
                initial_not_before: not_before,
                producer_id,
                ..Default::default()
            };

            match queue.enqueue(input) {
                EnqueueOutcome::Committed(ticket) => {
                    println!("job_id: {}", steadq_names::hex_encode(&ticket.job_id));
                    println!("path: {}", ticket.expected_relative_path);
                    ExitCode::SUCCESS
                }
                EnqueueOutcome::NotCommitted(ticket, err) => {
                    eprintln!("not committed: {err}");
                    if ticket.job_id != [0; 16] {
                        eprintln!("job_id: {}", steadq_names::hex_encode(&ticket.job_id));
                    }
                    ExitCode::FAILURE
                }
                EnqueueOutcome::OutcomeUnknown(ticket, err) => {
                    eprintln!("outcome unknown: {err}");
                    eprintln!("job_id: {}", steadq_names::hex_encode(&ticket.job_id));
                    eprintln!("path: {}", ticket.expected_relative_path);
                    ExitCode::from(2)
                }
            }
        }

        Commands::Lease {
            path,
            duration_seconds,
            handle_file,
            ticket_out,
        } => {
            let queue = match Queue::open(&path, &OpenOptions::default()) {
                Ok(q) => q,
                Err(e) => {
                    eprintln!("open failed: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let mut queue = queue;

            let duration_ns = match parse_duration_seconds(duration_seconds) {
                Some(ns) => ns,
                None => {
                    eprintln!("invalid duration: overflow");
                    return ExitCode::FAILURE;
                }
            };
            match queue.lease(0, duration_ns) {
                LeaseOutcome::Leased(lease) => {
                    if let Some(ref hf) = handle_file {
                        if let Err(e) =
                            save_handle_to_file(&path, &queue.format().queue_id, hf, &lease)
                        {
                            eprintln!("warning: failed to write handle file: {e}");
                        }
                    }
                    println!("job_id: {}", steadq_names::hex_encode(&lease.job_id));
                    println!("generation: {}", lease.generation);
                    println!("attempt: {}/{}", lease.attempt, lease.maximum_attempts);
                    ExitCode::SUCCESS
                }
                LeaseOutcome::Empty => {
                    eprintln!("no jobs available");
                    ExitCode::FAILURE
                }
                LeaseOutcome::NotCommitted(e) => {
                    eprintln!("lease failed: {e}");
                    ExitCode::FAILURE
                }
                LeaseOutcome::OutcomeUnknown(ticket) => {
                    eprintln!("outcome unknown");
                    eprintln!("job_id: {}", steadq_names::hex_encode(&ticket.job_id()));
                    // P1-19: Persist ticket for later resolution.
                    if let Some(ref tf) = ticket_out {
                        match write_ticket_file(tf, &ticket) {
                            Ok(()) => eprintln!("ticket written to: {}", tf.display()),
                            Err(e) => eprintln!("warning: failed to write ticket: {e}"),
                        }
                    }
                    ExitCode::from(2)
                }
            }
        }

        Commands::Stats { path } => {
            match Queue::open(&path, &OpenOptions::default()) {
                Ok(_queue) => {
                    let root = &path;
                    let mut stats_map: std::collections::BTreeMap<String, usize> =
                        std::collections::BTreeMap::new();
                    for state in [
                        "ready",
                        "leased",
                        "delayed",
                        "receipts",
                        "dead",
                        "quarantine",
                    ] {
                        let state_path = root.join(state);
                        if state_path.exists() {
                            let count = count_files_recursive(&state_path);
                            stats_map.insert(state.to_string(), count);
                        }
                    }
                    // C-59: Support global --json
                    if cli.json {
                        println!("{}", serde_json::to_string_pretty(&stats_map).unwrap());
                    } else {
                        for (state, count) in &stats_map {
                            println!("{state}: {count}");
                        }
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("open failed: {e}");
                    ExitCode::FAILURE
                }
            }
        }

        Commands::Doctor { path, json } => {
            let mut results: Vec<(&str, String, bool)> = Vec::new();

            // boot_id
            match steadq_fs_linux::read_boot_id() {
                Ok(id) => results.push(("boot_id", id, true)),
                Err(e) => results.push(("boot_id", e.to_string(), false)),
            }
            // clock_boottime
            match steadq_fs_linux::clock_boottime_ns() {
                Ok(ns) => results.push(("clock_boottime", format!("{ns} ns"), true)),
                Err(e) => results.push(("clock_boottime", e.to_string(), false)),
            }
            // clock_realtime
            match steadq_fs_linux::clock_realtime_ns() {
                Ok(ns) => results.push(("clock_realtime", format!("{ns} ns"), true)),
                Err(e) => results.push(("clock_realtime", e.to_string(), false)),
            }
            // getrandom
            match steadq_fs_linux::random_128bit() {
                Ok(_) => results.push(("getrandom", "OK".to_string(), true)),
                Err(e) => results.push(("getrandom", e.to_string(), false)),
            }

            if path.exists() {
                // filesystem type
                match steadq_fs_linux::statfs(&path) {
                    Ok(stat) => {
                        let ft = stat.f_type;
                        // R4-H19: Refused filesystems are not OK
                        let (fs_name, fs_ok) = if ft == steadq_fs_linux::EXT4_SUPER_MAGIC {
                            ("ext4", true)
                        } else if ft == steadq_fs_linux::XFS_SUPER_MAGIC {
                            ("xfs", true)
                        } else if ft == steadq_fs_linux::TMPFS_MAGIC {
                            ("tmpfs_not_certified", false)
                        } else if ft == steadq_fs_linux::NFS_SUPER_MAGIC {
                            ("nfs_refused", false)
                        } else if ft == steadq_fs_linux::FUSE_SUPER_MAGIC {
                            ("fuse_refused", false)
                        } else if ft == steadq_fs_linux::OVERLAYFS_SUPER_MAGIC {
                            ("overlay_refused", false)
                        } else {
                            ("unknown_refused", false)
                        };
                        results.push(("filesystem", format!("{fs_name} (magic {ft:#x})"), fs_ok));
                    }
                    Err(e) => results.push(("filesystem", e.to_string(), false)),
                }

                // Publication mode probe under tmp/
                let probe_dir = path.join("tmp");
                if probe_dir.exists() {
                    match steadq_fs_linux::open_dir_absolute(&probe_dir) {
                        Ok(dir_fd) => {
                            match steadq_fs_linux::probe_publication_mode(dir_fd.as_raw_fd()) {
                                Ok(mode) => {
                                    let mode_str = match mode {
                                        steadq_fs_linux::PublicationMode::DirectAtEmptyPath => {
                                            "direct-at-empty-path"
                                        }
                                        steadq_fs_linux::PublicationMode::ProcSelfFd => {
                                            "proc-self-fd"
                                        }
                                        steadq_fs_linux::PublicationMode::NamedFallback => {
                                            "named-fallback"
                                        }
                                    };
                                    results.push(("publication_mode", mode_str.to_string(), true));
                                }
                                Err(e) => results.push(("publication_mode", e.to_string(), false)),
                            }
                            // rename probe
                            match steadq_fs_linux::probe_rename_noreplace(dir_fd.as_raw_fd()) {
                                Ok(supported) => results.push((
                                    "rename_noreplace",
                                    if supported {
                                        "supported".into()
                                    } else {
                                        "unsupported".into()
                                    },
                                    supported,
                                )),
                                Err(e) => results.push(("rename_noreplace", e.to_string(), false)),
                            }
                            // dir fsync probe
                            match steadq_fs_linux::probe_dir_fsync(dir_fd.as_raw_fd()) {
                                Ok(supported) => results.push((
                                    "dir_fsync",
                                    if supported {
                                        "supported".into()
                                    } else {
                                        "unsupported".into()
                                    },
                                    supported,
                                )),
                                Err(e) => results.push(("dir_fsync", e.to_string(), false)),
                            }
                        }
                        Err(e) => {
                            results.push(("publication_mode", format!("open failed: {e}"), false))
                        }
                    }
                }
            }

            if json {
                let map: std::collections::BTreeMap<&str, serde_json::Value> = results
                    .iter()
                    .map(|(k, v, ok)| (*k, serde_json::json!({"value": v, "ok": ok})))
                    .collect();
                println!("{}", serde_json::to_string_pretty(&map).unwrap());
            } else {
                eprintln!("steadq doctor {}", path.display());
                for (k, v, ok) in &results {
                    eprintln!("  {}: {}{}", k, v, if *ok { "" } else { " [FAIL]" });
                }
            }
            // R2-H22: Exit failure if any check failed.
            let all_ok = results.iter().all(|(_, _, ok)| *ok);
            if all_ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(EXIT_IO_FAILURE)
            }
        }

        Commands::Ack { path, handle_file } => {
            let mut queue = match Queue::open(&path, &OpenOptions::default()) {
                Ok(q) => q,
                Err(e) => {
                    eprintln!("open failed: {e}");
                    return ExitCode::from(EXIT_IO_FAILURE);
                }
            };
            let lease = match load_handle(&handle_file, &queue.format().queue_id) {
                Ok(q) => q,
                Err(e) => {
                    eprintln!("open failed: {e}");
                    return ExitCode::FAILURE;
                }
            };
            // R2-H19: CLI uses strict ack path: verify payload first.
            // P1-17: ack() already performs strict payload verification.
            // Don't call verify_lease_payload() separately to avoid double hashing.
            match queue.ack(&lease) {
                steadq_core::AckOutcome::Acked => {
                    eprintln!("acked");
                    ExitCode::SUCCESS
                }
                steadq_core::AckOutcome::AlreadyAcked => {
                    eprintln!("already acked (idempotent success)");
                    ExitCode::SUCCESS
                }
                steadq_core::AckOutcome::LeaseLost => {
                    eprintln!("lease lost");
                    ExitCode::FAILURE
                }
                steadq_core::AckOutcome::NotCommitted(e) => {
                    eprintln!("not committed: {e}");
                    ExitCode::FAILURE
                }
                steadq_core::AckOutcome::OutcomeUnknown(_) => {
                    eprintln!("outcome unknown");
                    ExitCode::from(2)
                }
            }
        }

        Commands::Retry {
            path,
            handle_file,
            after_seconds,
        } => {
            let mut queue = match Queue::open(&path, &OpenOptions::default()) {
                Ok(q) => q,
                Err(e) => {
                    eprintln!("open failed: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let lease = match load_handle(&handle_file, &queue.format().queue_id) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("handle load failed: {e}");
                    return ExitCode::FAILURE;
                }
            };
            // R2-H20: Use Queue::retry_after() which uses the rollback-safe
            // effective wall clock.
            let outcome = match after_seconds {
                Some(s) => {
                    let duration_ns = s.saturating_mul(1_000_000_000);
                    queue.retry_after(&lease, duration_ns)
                }
                None => queue.retry_now(&lease),
            };
            match outcome {
                steadq_core::TransitionOutcome::Committed => {
                    eprintln!("retried");
                    ExitCode::SUCCESS
                }
                steadq_core::TransitionOutcome::LeaseLost => {
                    eprintln!("lease lost");
                    ExitCode::FAILURE
                }
                steadq_core::TransitionOutcome::NotCommitted(e) => {
                    eprintln!("not committed: {e}");
                    ExitCode::FAILURE
                }
                steadq_core::TransitionOutcome::OutcomeUnknown(_) => {
                    eprintln!("outcome unknown");
                    ExitCode::from(2)
                }
            }
        }

        Commands::Bury {
            path,
            handle_file,
            reason,
        } => {
            let mut queue = match Queue::open(&path, &OpenOptions::default()) {
                Ok(q) => q,
                Err(e) => {
                    eprintln!("open failed: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let lease = match load_handle(&handle_file, &queue.format().queue_id) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("handle load failed: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let reason = steadq_core::DeadReason::from_u16(reason)
                .unwrap_or(steadq_core::DeadReason::Unspecified);
            match queue.bury(&lease, reason) {
                steadq_core::TransitionOutcome::Committed => {
                    eprintln!("buried");
                    ExitCode::SUCCESS
                }
                steadq_core::TransitionOutcome::LeaseLost => {
                    eprintln!("lease lost");
                    ExitCode::FAILURE
                }
                steadq_core::TransitionOutcome::NotCommitted(e) => {
                    eprintln!("not committed: {e}");
                    ExitCode::FAILURE
                }
                steadq_core::TransitionOutcome::OutcomeUnknown(_) => {
                    eprintln!("outcome unknown");
                    ExitCode::from(2)
                }
            }
        }

        Commands::Inspect { path, job_id } => {
            let job_id_bytes = match steadq_names::hex_decode_16(&job_id) {
                Some(b) => b,
                None => {
                    eprintln!("invalid job_id: expected 32 lowercase hex chars");
                    return ExitCode::FAILURE;
                }
            };
            match Queue::open(&path, &OpenOptions::default()) {
                Ok(queue) => {
                    let snapshots = queue.inspect(&job_id_bytes);
                    if snapshots.is_empty() {
                        eprintln!("not found");
                        return ExitCode::FAILURE;
                    }
                    for s in &snapshots {
                        println!(
                            "{} gen={} attempt={}/{} {}",
                            s.state, s.generation, s.attempt, s.maximum_attempts, s.relative_path
                        );
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("open failed: {e}");
                    ExitCode::FAILURE
                }
            }
        }

        Commands::Verify { file, deep } => {
            let data = match std::fs::read(&file) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("read failed: {e}");
                    return ExitCode::FAILURE;
                }
            };
            if data.len() >= 128 && &data[0..8] == b"SDQJOB1\0" {
                match steadq_format::FixedHeader::decode(&data[0..128]) {
                    Ok(header) => {
                        eprintln!("job_id: {}", steadq_names::hex_encode(&header.job_id));
                        eprintln!("payload_length: {}", header.payload_length);
                        eprintln!("maximum_attempts: {}", header.maximum_attempts);
                        let expected_size = 128
                            + header.extension_header_length as usize
                            + header.payload_length as usize;
                        if data.len() != expected_size {
                            eprintln!(
                                "CORRUPT: expected {} bytes, got {}",
                                expected_size,
                                data.len()
                            );
                            return ExitCode::from(3);
                        }
                        // C-58: Verify envelope digest
                        let ext_bytes = &data[128..128 + header.extension_header_length as usize];
                        if !steadq_format::verify_envelope_digest(&header, ext_bytes) {
                            eprintln!("CORRUPT: envelope digest mismatch");
                            return ExitCode::from(3);
                        }
                        eprintln!("envelope_digest: verified");
                        if deep {
                            let payload = &data[128 + header.extension_header_length as usize..];
                            let computed = steadq_format::payload_digest(payload);
                            if computed != header.payload_digest {
                                eprintln!("CORRUPT: payload digest mismatch");
                                return ExitCode::from(3);
                            }
                            eprintln!("payload_digest: verified");
                        }
                        eprintln!("valid");
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("CORRUPT: {e}");
                        ExitCode::from(3)
                    }
                }
            } else if data.len() == 160 && &data[0..8] == b"SDQFMT1\0" {
                match steadq_format::FormatRecord::decode(&data) {
                    Ok(fmt) => {
                        eprintln!("queue_id: {}", steadq_names::hex_encode(&fmt.queue_id));
                        eprintln!("shard_count: {}", fmt.shard_count);
                        eprintln!("valid");
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("CORRUPT: {e}");
                        ExitCode::from(3)
                    }
                }
            } else {
                eprintln!("unknown format");
                ExitCode::FAILURE
            }
        }

        Commands::FormatDump { file } => {
            let data = match std::fs::read(&file) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("read failed: {e}");
                    return ExitCode::FAILURE;
                }
            };
            if data.len() >= 128 && &data[0..8] == b"SDQJOB1\0" {
                match steadq_format::FixedHeader::decode(&data[0..128]) {
                    Ok(h) => {
                        println!("type: job");
                        println!("job_id: {}", steadq_names::hex_encode(&h.job_id));
                        println!("payload_length: {}", h.payload_length);
                        println!("extension_header_length: {}", h.extension_header_length);
                        println!("maximum_attempts: {}", h.maximum_attempts);
                        println!(
                            "payload_digest: {}",
                            steadq_names::hex_encode(&h.payload_digest)
                        );
                        println!(
                            "envelope_digest: {}",
                            steadq_names::hex_encode(&h.envelope_digest)
                        );
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("parse error: {e}");
                        ExitCode::FAILURE
                    }
                }
            } else if data.len() == 160 && &data[0..8] == b"SDQFMT1\0" {
                match steadq_format::FormatRecord::decode(&data) {
                    Ok(f) => {
                        println!("type: format");
                        println!("queue_id: {}", steadq_names::hex_encode(&f.queue_id));
                        println!("shard_count: {}", f.shard_count);
                        println!("lease_bucket_width_ns: {}", f.lease_bucket_width_ns);
                        println!("delayed_bucket_width_ns: {}", f.delayed_bucket_width_ns);
                        println!("terminal_bucket_width_ns: {}", f.terminal_bucket_width_ns);
                        println!("max_payload_length: {}", f.max_payload_length);
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("parse error: {e}");
                        ExitCode::FAILURE
                    }
                }
            } else {
                eprintln!("unrecognized format");
                ExitCode::FAILURE
            }
        }

        Commands::Recover {
            path,
            watch,
            budget_ops,
            budget_ms,
        } => {
            let budget = steadq_core::WorkBudget {
                max_operations: budget_ops,
                max_duration_ms: budget_ms,
            };
            loop {
                let mut queue = match Queue::open(&path, &OpenOptions::default()) {
                    Ok(q) => q,
                    Err(e) => {
                        eprintln!("open failed: {e}");
                        return ExitCode::FAILURE;
                    }
                };
                let stats = queue.recover(&budget);
                eprintln!(
                    "reaped:{} promoted:{} temp_deleted:{} dead:{} ops:{}{}",
                    stats.leases_reaped,
                    stats.delayed_promoted,
                    stats.temp_files_deleted,
                    stats.leases_to_dead,
                    stats.operations_attempted,
                    if stats.budget_exhausted {
                        " (budget exhausted)"
                    } else {
                        ""
                    },
                );
                if !stats.errors.is_empty() {
                    eprintln!("{} recovery errors", stats.errors.len());
                }
                if !watch {
                    if stats.errors.is_empty() {
                        break;
                    } else {
                        return ExitCode::from(EXIT_IO_FAILURE);
                    }
                }
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
            ExitCode::SUCCESS
        }
        Commands::Resolve {
            path,
            result_file,
            stabilize,
        } => {
            let data = match std::fs::read(&result_file) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("read result file failed: {e}");
                    return ExitCode::from(EXIT_ORDINARY);
                }
            };
            let ticket = match steadq_core::TransitionTicket::from_json(&data) {
                Ok(ticket) => ticket,
                Err(error) => {
                    eprintln!("invalid transition ticket: {error}");
                    return ExitCode::from(EXIT_ORDINARY);
                }
            };

            let queue = match Queue::open(&path, &OpenOptions::default()) {
                Ok(q) => q,
                Err(e) => {
                    eprintln!("open failed: {e}");
                    return ExitCode::from(EXIT_IO_FAILURE);
                }
            };
            let (source_path, dest_path) = match queue.transition_ticket_paths(&ticket) {
                Ok(paths) => paths,
                Err(error) => {
                    eprintln!("invalid transition ticket: {error}");
                    return ExitCode::from(EXIT_ORDINARY);
                }
            };

            let outcome = queue.resolve(&ticket, stabilize);
            match outcome {
                steadq_core::ResolutionOutcome::DestinationObserved
                | steadq_core::ResolutionOutcome::DestinationStabilized => {
                    eprintln!("destination observed: {dest_path}");
                    ExitCode::SUCCESS
                }
                steadq_core::ResolutionOutcome::SourceObserved
                | steadq_core::ResolutionOutcome::SourceStabilized => {
                    eprintln!("source observed: {source_path}");
                    ExitCode::SUCCESS
                }
                steadq_core::ResolutionOutcome::BothObserved => {
                    eprintln!("both source and destination observed (corruption)");
                    ExitCode::from(EXIT_CORRUPTION)
                }
                steadq_core::ResolutionOutcome::NeitherObserved => {
                    eprintln!("neither source nor destination observed");
                    ExitCode::from(EXIT_ORDINARY)
                }
                steadq_core::ResolutionOutcome::ConflictingObject => {
                    eprintln!("conflicting object at expected path");
                    ExitCode::from(EXIT_CORRUPTION)
                }
                steadq_core::ResolutionOutcome::ResolutionFailed(e) => {
                    eprintln!("resolution failed: {e}");
                    ExitCode::from(EXIT_IO_FAILURE)
                }
            }
        }

        Commands::Bench {
            path,
            producers,
            consumers,
            duration_seconds,
            payload_size,
            lease_duration_seconds,
        } => {
            eprintln!(
                "bench: {producers} producers, {consumers} consumers, {duration_seconds}s, {payload_size}B payload"
            );

            let payload = vec![0x42u8; payload_size];
            let duration = std::time::Duration::from_secs(duration_seconds);
            let deadline = std::time::Instant::now() + duration;

            use std::sync::atomic::{AtomicU64, Ordering};
            use std::sync::Arc;
            use std::thread;

            let enqueued = Arc::new(AtomicU64::new(0));
            let leased = Arc::new(AtomicU64::new(0));
            let acked = Arc::new(AtomicU64::new(0));

            let mut handles = Vec::new();

            // Producers - P-05: reuse one queue handle per worker
            for _ in 0..producers {
                let p = path.clone();
                let payload = payload.clone();
                let enqueued = enqueued.clone();
                let dl = deadline;
                handles.push(thread::spawn(move || {
                    // P-05: Open once per worker, not per operation
                    let mut queue = Queue::open(
                        &p,
                        &OpenOptions {
                            allow_unsupported_fs: true,
                            ..Default::default()
                        },
                    )
                    .unwrap();
                    while std::time::Instant::now() < dl {
                        if let steadq_core::EnqueueOutcome::Committed(_) =
                            queue.enqueue(EnqueueInput {
                                maximum_attempts: 3,
                                content_type: "bench".to_string(),
                                payload: payload.clone(),
                                ..Default::default()
                            })
                        {
                            enqueued.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }));
            }

            // Consumers - P-05: reuse one queue handle per worker
            let lease_ns = lease_duration_seconds * 1_000_000_000;
            for _ in 0..consumers {
                let p = path.clone();
                let leased = leased.clone();
                let acked = acked.clone();
                let dl = deadline;
                handles.push(thread::spawn(move || {
                    // P-05: Open once per worker
                    let mut queue = Queue::open(
                        &p,
                        &OpenOptions {
                            allow_unsupported_fs: true,
                            ..Default::default()
                        },
                    )
                    .unwrap();
                    while std::time::Instant::now() < dl {
                        match queue.lease(0, lease_ns) {
                            steadq_core::LeaseOutcome::Leased(l) => {
                                leased.fetch_add(1, Ordering::Relaxed);
                                if queue.ack_unverified(&l) == steadq_core::AckOutcome::Acked {
                                    acked.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            _ => {
                                thread::sleep(std::time::Duration::from_millis(1));
                            }
                        }
                    }
                }));
            }

            for h in handles {
                h.join().unwrap();
            }

            let elapsed = duration_seconds as f64;
            let eq = enqueued.load(Ordering::Relaxed);
            let lq = leased.load(Ordering::Relaxed);
            let aq = acked.load(Ordering::Relaxed);

            eprintln!("enqueued: {} ({:.0}/s)", eq, eq as f64 / elapsed);
            eprintln!("leased: {} ({:.0}/s)", lq, lq as f64 / elapsed);
            eprintln!("acked: {} ({:.0}/s)", aq, aq as f64 / elapsed);
            ExitCode::from(EXIT_SUCCESS)
        }

        Commands::Admin { command } => match command {
            AdminCommands::DeadList { path } => {
                let qroot = path.join("dead");
                if let Ok(entries) = std::fs::read_dir(&qroot) {
                    for bucket in entries.flatten() {
                        if let Ok(shards) = std::fs::read_dir(bucket.path()) {
                            for shard in shards.flatten() {
                                if let Ok(files) = std::fs::read_dir(shard.path()) {
                                    for file in files.flatten() {
                                        let name = file.file_name().to_string_lossy().to_string();
                                        let rp = file
                                            .path()
                                            .strip_prefix(&path)
                                            .unwrap_or(&file.path())
                                            .display()
                                            .to_string();
                                        println!("{name} {rp}");
                                    }
                                }
                            }
                        }
                    }
                }
                ExitCode::from(EXIT_SUCCESS)
            }
            AdminCommands::DeadInspect { path, job_id } => {
                let job_id_bytes = match steadq_names::hex_decode_16(&job_id) {
                    Some(b) => b,
                    None => return ExitCode::from(EXIT_ORDINARY),
                };
                let queue = match Queue::open(&path, &OpenOptions::default()) {
                    Ok(q) => q,
                    Err(_) => return ExitCode::from(EXIT_IO_FAILURE),
                };
                for s in queue
                    .inspect(&job_id_bytes)
                    .iter()
                    .filter(|s| s.state == "dead")
                {
                    println!(
                        "gen={} attempt={}/{} {}",
                        s.generation, s.attempt, s.maximum_attempts, s.relative_path
                    );
                }
                ExitCode::from(EXIT_SUCCESS)
            }
            AdminCommands::DeadExport {
                path,
                job_id,
                output,
            } => {
                let job_id_bytes = steadq_names::hex_decode_16(&job_id).unwrap_or([0; 16]);
                let queue = match Queue::open(&path, &OpenOptions::default()) {
                    Ok(q) => q,
                    Err(_) => return ExitCode::from(EXIT_IO_FAILURE),
                };
                match queue
                    .inspect(&job_id_bytes)
                    .iter()
                    .find(|s| s.state == "dead")
                {
                    Some(s) => match std::fs::copy(path.join(&s.relative_path), &output) {
                        Ok(n) => {
                            eprintln!("exported {n} bytes");
                            ExitCode::from(EXIT_SUCCESS)
                        }
                        Err(_) => ExitCode::from(EXIT_IO_FAILURE),
                    },
                    None => {
                        eprintln!("not found");
                        ExitCode::from(EXIT_ORDINARY)
                    }
                }
            }
            AdminCommands::DeadRemove { path, job_id } => {
                let job_id_bytes = steadq_names::hex_decode_16(&job_id).unwrap_or([0; 16]);
                let queue = match Queue::open(&path, &OpenOptions::default()) {
                    Ok(q) => q,
                    Err(_) => return ExitCode::from(EXIT_IO_FAILURE),
                };
                match queue
                    .inspect(&job_id_bytes)
                    .iter()
                    .find(|s| s.state == "dead")
                {
                    Some(s) => match std::fs::remove_file(path.join(&s.relative_path)) {
                        Ok(()) => {
                            eprintln!("removed");
                            ExitCode::from(EXIT_SUCCESS)
                        }
                        Err(_) => ExitCode::from(EXIT_IO_FAILURE),
                    },
                    None => {
                        eprintln!("not found");
                        ExitCode::from(EXIT_ORDINARY)
                    }
                }
            }
            AdminCommands::QuarantineList { path } => {
                let queue = match Queue::open(&path, &OpenOptions::default()) {
                    Ok(q) => q,
                    Err(_) => return ExitCode::from(EXIT_IO_FAILURE),
                };
                for entry in queue.list_quarantine() {
                    println!(
                        "{} reason=0x{:04x} {}",
                        steadq_names::hex_encode(&entry.quarantine_id),
                        entry.reason,
                        entry.relative_path
                    );
                }
                ExitCode::from(EXIT_SUCCESS)
            }
            AdminCommands::QuarantineInspect {
                path,
                quarantine_id,
            } => {
                let qid = match steadq_names::hex_decode_16(&quarantine_id) {
                    Some(b) => b,
                    None => {
                        eprintln!("invalid quarantine_id");
                        return ExitCode::from(EXIT_ORDINARY);
                    }
                };
                let queue = match Queue::open(&path, &OpenOptions::default()) {
                    Ok(q) => q,
                    Err(_) => return ExitCode::from(EXIT_IO_FAILURE),
                };
                match queue.find_quarantine(&qid) {
                    Some(entry) => {
                        let abs = path.join(&entry.relative_path);
                        let meta = std::fs::metadata(&abs).ok();
                        let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
                        println!(
                            "quarantine_id={} reason=0x{:04x} path={} size={size}",
                            steadq_names::hex_encode(&entry.quarantine_id),
                            entry.reason,
                            entry.relative_path
                        );
                        ExitCode::from(EXIT_SUCCESS)
                    }
                    None => {
                        eprintln!("not found");
                        ExitCode::from(EXIT_ORDINARY)
                    }
                }
            }
            AdminCommands::QuarantineExport {
                path,
                quarantine_id,
                output,
            } => {
                let qid = match steadq_names::hex_decode_16(&quarantine_id) {
                    Some(b) => b,
                    None => {
                        eprintln!("invalid quarantine_id");
                        return ExitCode::from(EXIT_ORDINARY);
                    }
                };
                let queue = match Queue::open(&path, &OpenOptions::default()) {
                    Ok(q) => q,
                    Err(_) => return ExitCode::from(EXIT_IO_FAILURE),
                };
                match queue.export_quarantine(&qid, &output) {
                    Ok(n) => {
                        eprintln!("exported {n} bytes");
                        ExitCode::from(EXIT_SUCCESS)
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        eprintln!("not found");
                        ExitCode::from(EXIT_ORDINARY)
                    }
                    Err(_) => ExitCode::from(EXIT_IO_FAILURE),
                }
            }
            AdminCommands::QuarantineRemove {
                path,
                quarantine_id,
            } => {
                let qid = match steadq_names::hex_decode_16(&quarantine_id) {
                    Some(b) => b,
                    None => {
                        eprintln!("invalid quarantine_id");
                        return ExitCode::from(EXIT_ORDINARY);
                    }
                };
                let queue = match Queue::open(&path, &OpenOptions::default()) {
                    Ok(q) => q,
                    Err(_) => return ExitCode::from(EXIT_IO_FAILURE),
                };
                match queue.remove_quarantine(&qid) {
                    Ok(true) => {
                        eprintln!("removed");
                        ExitCode::from(EXIT_SUCCESS)
                    }
                    Ok(false) => {
                        eprintln!("not found");
                        ExitCode::from(EXIT_ORDINARY)
                    }
                    Err(_) => ExitCode::from(EXIT_IO_FAILURE),
                }
            }
            AdminCommands::CompactReceipts { path } => {
                let mut queue = match Queue::open(&path, &OpenOptions::default()) {
                    Ok(q) => q,
                    Err(_) => return ExitCode::from(EXIT_IO_FAILURE),
                };
                let stats = queue.recover(&steadq_core::WorkBudget::default());
                eprintln!(
                    "compacted: {} expired: {}",
                    stats.receipts_compacted, stats.receipts_expired
                );
                ExitCode::from(EXIT_SUCCESS)
            }
        },
    }
}

fn count_files_recursive(path: &std::path::Path) -> usize {
    let mut count = 0;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                count += count_files_recursive(&p);
            } else {
                count += 1;
            }
        }
    }
    count
}

#[derive(serde::Serialize, serde::Deserialize)]
struct HandleFile {
    queue_root: String,
    #[serde(default)]
    queue_id: Option<String>,
    job_id: String,
    generation: u64,
    attempt: u32,
    maximum_attempts: u32,
    token: String,
    boot_id: String,
    expires_boottime_ns: u64,
    expires_wall_ns: u64,
    expected_dev: u64,
    expected_inode: u64,
    exact_source_path: String,
    envelope_digest: String,
}

fn write_ticket_file(
    path: &std::path::Path,
    ticket: &steadq_core::TransitionTicket,
) -> std::io::Result<()> {
    let json = ticket
        .to_json()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string()))?;
    let rand_bytes = steadq_fs_linux::random_128bit()
        .map(|b| steadq_names::hex_encode(&b))
        .unwrap_or_else(|_| format!("{}", std::process::id()));
    let tmp_path = path.with_extension(format!("tmp.{rand_bytes}"));
    std::fs::write(&tmp_path, json)?;
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

fn save_handle_to_file(
    queue_root: &std::path::Path,
    queue_id: &[u8; 16],
    handle_path: &std::path::Path,
    lease: &steadq_core::LeaseInfo,
) -> std::io::Result<()> {
    let handle = HandleFile {
        queue_root: queue_root.display().to_string(),
        queue_id: Some(steadq_names::hex_encode(queue_id)),
        job_id: steadq_names::hex_encode(&lease.job_id),
        generation: lease.generation,
        attempt: lease.attempt,
        maximum_attempts: lease.maximum_attempts,
        token: steadq_names::hex_encode(&lease.token),
        boot_id: lease.boot_id.clone(),
        expires_boottime_ns: lease.expires_boottime_ns,
        expires_wall_ns: lease.expires_wall_ns,
        expected_dev: lease.expected_dev,
        expected_inode: lease.expected_inode,
        exact_source_path: lease.exact_source_path.clone(),
        envelope_digest: steadq_names::hex_encode(&lease.envelope_digest),
    };
    let json = serde_json::to_string_pretty(&handle)?;

    // R2-M14: Atomic write with unique temp name (not deterministic)
    let rand_bytes = steadq_fs_linux::random_128bit()
        .map(|b| steadq_names::hex_encode(&b))
        .unwrap_or_else(|_| format!("{}", std::process::id()));
    let tmp_path = handle_path.with_extension(format!("tmp.{rand_bytes}"));
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        use std::io::Write;
        let mut file = opts.open(&tmp_path)?;
        file.write_all(json.as_bytes())?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp_path, handle_path)?;
    // C-55: Sync parent directory
    if let Some(parent) = handle_path.parent() {
        if let Ok(parent_dir) = std::fs::File::open(parent) {
            let _ = parent_dir.sync_all();
        }
    }
    Ok(())
}

fn load_handle(
    path: &std::path::Path,
    queue_id: &[u8; 16],
) -> std::io::Result<steadq_core::LeaseInfo> {
    let data = std::fs::read(path)?;
    let handle: HandleFile = serde_json::from_slice(&data)?;
    let job_id = steadq_names::hex_decode_16(&handle.job_id)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad job_id"))?;
    let token = steadq_names::hex_decode_16(&handle.token)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad token"))?;
    let envelope_digest =
        steadq_names::hex_decode_32(&handle.envelope_digest).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bad envelope_digest: expected 64 lowercase hex chars",
            )
        })?;

    // P1-21: Verify queue binding. Queue id must be present and must match.
    match handle.queue_id.as_ref() {
        Some(hqid) => match steadq_names::hex_decode_16(hqid) {
            Some(handle_qid) if handle_qid == *queue_id => {}
            Some(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "handle file queue_id does not match target queue",
                ));
            }
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "handle file queue_id is not 32 lowercase hex chars",
                ));
            }
        },
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "handle file missing queue_id binding",
            ));
        }
    }

    Ok(steadq_core::LeaseInfo {
        job_id,
        envelope_digest,
        generation: handle.generation,
        attempt: handle.attempt,
        maximum_attempts: handle.maximum_attempts,
        token,
        boot_id: handle.boot_id,
        expires_boottime_ns: handle.expires_boottime_ns,
        expires_wall_ns: handle.expires_wall_ns,
        content_type: String::new(),
        payload_length: 0,
        payload_digest: [0; 32],
        expected_dev: handle.expected_dev,
        expected_inode: handle.expected_inode,
        exact_source_path: handle.exact_source_path,
    })
}
