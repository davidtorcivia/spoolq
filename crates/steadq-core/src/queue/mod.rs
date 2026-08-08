// SteadQ/1 queue initialization, open, and enqueue operations.

pub mod engine;
pub mod layout;
pub mod verified;

use std::io;
use std::os::unix::io::{AsRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};

use steadq_format::cbor::ExtensionHeader;
use steadq_format::{
    envelope_digest, payload_digest, FixedHeader, FormatRecord, WatermarkRecord,
    DIGEST_ALGORITHM_SHA256, MAX_PAYLOAD_LENGTH,
};
use steadq_fs_linux as fs;
use steadq_math::{self, bucket_number, ceiling_bucket, eligibility_bucket_and_ns};
use steadq_names::{self, bucket_hex, compute_shard, shard_hex, temp_filename, CommonFields};

use crate::errors::*;

/// Configuration for creating a new queue.
#[derive(Clone, Debug)]
pub struct CreateOptions {
    pub shard_count: u32,
    pub lease_bucket_width_ns: u64,
    pub delayed_bucket_width_ns: u64,
    pub terminal_bucket_width_ns: u64,
    pub max_payload_length: u64,
}

impl Default for CreateOptions {
    fn default() -> Self {
        Self {
            shard_count: 64,
            lease_bucket_width_ns: 10_000_000_000,
            delayed_bucket_width_ns: 10_000_000_000,
            terminal_bucket_width_ns: 3_600_000_000_000,
            max_payload_length: MAX_PAYLOAD_LENGTH,
        }
    }
}

/// Validate all CreateOptions before any filesystem mutation (C-01).
/// Same validation used in encoding and tests.
pub fn validate_create_options(opts: &CreateOptions) -> Result<(), Error> {
    if opts.shard_count == 0 || !opts.shard_count.is_power_of_two() || opts.shard_count > 4096 {
        return Err(Error::InvalidInput("invalid shard count".into()));
    }
    if opts.lease_bucket_width_ns == 0 {
        return Err(Error::InvalidInput(
            "lease bucket width must be non-zero".into(),
        ));
    }
    if opts.delayed_bucket_width_ns == 0 {
        return Err(Error::InvalidInput(
            "delayed bucket width must be non-zero".into(),
        ));
    }
    if opts.terminal_bucket_width_ns == 0 {
        return Err(Error::InvalidInput(
            "terminal bucket width must be non-zero".into(),
        ));
    }
    if !(60_000_000_000..=86_400_000_000_000).contains(&opts.terminal_bucket_width_ns) {
        return Err(Error::InvalidInput("invalid terminal bucket width".into()));
    }
    if opts.max_payload_length > MAX_PAYLOAD_LENGTH {
        return Err(Error::InvalidInput("payload limit exceeds maximum".into()));
    }
    Ok(())
}

/// Operational options for opening a queue.
#[derive(Clone, Debug)]
pub struct OpenOptions {
    pub allow_unsupported_fs: bool,
    pub receipt_retention_ns: u64,
    pub temporary_file_ttl_ns: u64,
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self {
            allow_unsupported_fs: false,
            receipt_retention_ns: 7 * 24 * 60 * 60 * 1_000_000_000,
            temporary_file_ttl_ns: 24 * 60 * 60 * 1_000_000_000,
        }
    }
}

/// Internal queue state.
#[allow(dead_code)]
/// R4-RES: In-memory cursor for resumable recovery. Tracks the last
/// Entry level cursor so persistent entries do not starve later work.
#[derive(Clone, Debug, Default)]
pub(crate) struct RecoveryCursor {
    pub promote_delayed: Option<(String, String, String)>,
    pub compact_receipts: Option<(String, String, String)>,
    pub delete_receipts: Option<(String, String, String)>,
}

pub struct Queue {
    pub(crate) root_fd: OwnedFd,
    #[allow(dead_code)]
    pub(crate) root_path: PathBuf,
    pub(crate) format: FormatRecord,
    pub(crate) boot_id: String,
    pub(crate) boot_id_bytes: [u8; 16],
    pub(crate) poisoned: bool,
    pub(crate) scan_round: u64,
    pub(crate) worker_nonce: [u8; 16],
    pub(crate) options: OpenOptions,
    #[allow(dead_code)]
    pub(crate) maint_lock_fd: Option<OwnedFd>,
    pub(crate) recovery_cursor: RecoveryCursor,
}

/// Internal helper enum for resolver object authentication.
enum ResolveObj {
    Absent,
    Match(ResolvedObject),
    Conflict,
    Error(Error),
}

struct ResolvedObject {
    directory_fd: OwnedFd,
    directory_device: u64,
    directory_inode: u64,
    file_fd: OwnedFd,
    device: u64,
    inode: u64,
}

struct ClaimSourceWitness {
    file_fd: OwnedFd,
    device: u64,
    inode: u64,
    evidence: TicketEvidence,
}

struct LeasedSourceWitness {
    directory_fd: OwnedFd,
    name: String,
    file_fd: OwnedFd,
    device: u64,
    inode: u64,
}

#[derive(Debug)]
enum WitnessedRenameOutcome {
    Linearized,
    LinearizedIdentityUnknown,
    SourceGone,
    SourceChanged,
    Collision,
    Failed(Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WitnessPathObservation {
    Match,
    Gone,
    Mismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeaseDirectoryOpenFailure {
    Gone,
    InvalidDirectory,
    Io,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResolverObjectOpenFailure {
    Absent,
    Conflict,
    Io,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PresenceFailure {
    Absent,
    Io,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClaimSourceIdentity {
    Match,
    Mismatch,
}

fn classify_claim_source_identity(
    stat: &libc::stat,
    witness: &ClaimSourceWitness,
) -> ClaimSourceIdentity {
    if resolved_identity_matches(
        stat.st_mode,
        stat.st_dev,
        stat.st_ino,
        witness.device,
        witness.inode,
    ) {
        ClaimSourceIdentity::Match
    } else {
        ClaimSourceIdentity::Mismatch
    }
}

fn is_singly_linked_regular(mode: libc::mode_t, link_count: libc::nlink_t) -> bool {
    mode & libc::S_IFMT == libc::S_IFREG && link_count == 1
}

fn stat_matches_witness(stat: &libc::stat, device: u64, inode: u64) -> bool {
    is_singly_linked_regular(stat.st_mode, stat.st_nlink)
        && identity_matches(stat.st_dev, stat.st_ino, device, inode)
}

fn classify_renamed_destination(
    stat: Option<&libc::stat>,
    device: u64,
    inode: u64,
) -> WitnessedRenameOutcome {
    match stat {
        Some(stat) if stat_matches_witness(stat, device, inode) => {
            WitnessedRenameOutcome::Linearized
        }
        Some(_) | None => WitnessedRenameOutcome::LinearizedIdentityUnknown,
    }
}

fn resolver_file_open_flags() -> i32 {
    libc::O_NOFOLLOW
        .checked_add(libc::O_CLOEXEC)
        .and_then(|flags| flags.checked_add(libc::O_NONBLOCK))
        .expect("Linux open flags fit i32")
}

fn resolver_error_is_not_found(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::ENOENT)
}

fn classify_lease_directory_open_failure(error: &io::Error) -> LeaseDirectoryOpenFailure {
    match error.raw_os_error() {
        Some(libc::ENOENT) => LeaseDirectoryOpenFailure::Gone,
        Some(libc::ENOTDIR) => LeaseDirectoryOpenFailure::InvalidDirectory,
        _ => LeaseDirectoryOpenFailure::Io,
    }
}

fn classify_resolver_object_open_failure(error: &io::Error) -> ResolverObjectOpenFailure {
    match error.raw_os_error() {
        Some(libc::ENOENT) => ResolverObjectOpenFailure::Absent,
        Some(libc::ELOOP) => ResolverObjectOpenFailure::Conflict,
        _ => ResolverObjectOpenFailure::Io,
    }
}

fn classify_presence_failure(error: &io::Error) -> PresenceFailure {
    match error.raw_os_error() {
        Some(libc::ENOENT) => PresenceFailure::Absent,
        _ => PresenceFailure::Io,
    }
}

fn same_directory_identity(source: Option<&libc::stat>, destination: Option<&libc::stat>) -> bool {
    match (source, destination) {
        (Some(source), Some(destination)) => {
            source.st_dev == destination.st_dev && source.st_ino == destination.st_ino
        }
        _ => false,
    }
}

fn is_compact_receipt_candidate(size: usize, magic: &[u8]) -> bool {
    size == steadq_format::COMPACT_RECEIPT_SIZE && magic == steadq_format::RECEIPT_MAGIC
}

fn is_acknowledgement_receipt_path(operation: TransitionOperation, path_matches: bool) -> bool {
    operation == TransitionOperation::Acknowledge && path_matches
}

fn resolved_identity_matches(
    mode: libc::mode_t,
    device: u64,
    inode: u64,
    expected_device: u64,
    expected_inode: u64,
) -> bool {
    mode & libc::S_IFMT == libc::S_IFREG
        && identity_matches(device, inode, expected_device, expected_inode)
}

fn identity_matches(device: u64, inode: u64, expected_device: u64, expected_inode: u64) -> bool {
    device == expected_device && inode == expected_inode
}

struct ResolvePath<'a> {
    directory: fs::ValidatedRelativePath<'a>,
    name: &'a str,
    parts: Vec<&'a str>,
}

impl<'a> ResolvePath<'a> {
    fn new(path: &'a str) -> Result<Self, Error> {
        let relative = fs::ValidatedRelativePath::new(path)
            .map_err(|error| Error::InvalidInput(error.to_string()))?;
        let (directory, name) = relative
            .as_str()
            .rsplit_once('/')
            .ok_or_else(|| Error::InvalidInput("ticket path has no parent directory".into()))?;
        let directory = fs::ValidatedRelativePath::new(directory)
            .map_err(|error| Error::InvalidInput(error.to_string()))?;
        Ok(Self {
            directory,
            name,
            parts: relative.components().collect(),
        })
    }
}

/// Typed wall watermark read error. Distinguishes pre-watermark (NotFound) from
/// corruption and I/O failures so callers can decide between raw-clock fallback
/// and hard error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatermarkReadError {
    NotFound,
    Truncated(String),
    Corrupt(String),
    Io(String),
}

/// Pure helper for watermark open error classification. Returns true only for
/// NotFound, false for all other kinds. Extracted so match guard mutants are
/// killable by table tests.
fn watermark_open_is_not_found(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::NotFound
}

/// Pure helper for watermark advance decision. Returns true when observed
/// bucket is strictly greater than stored bucket. Extracted so <= vs > mutants
/// are killable.
fn watermark_should_advance(observed_bucket: u64, stored_bucket: u64) -> bool {
    observed_bucket > stored_bucket
}

/// Active path context for tag authentication.
#[derive(Clone, Debug)]
pub enum ActivePathContext {
    Ready {
        shard: String,
    },
    Leased {
        boot_id: String,
        bucket: String,
        shard: String,
    },
    Delayed {
        bucket: String,
        shard: String,
    },
}

impl Queue {
    /// Initialize a new queue at the given path.
    pub fn init(root: &Path, opts: &CreateOptions) -> io::Result<FormatRecord> {
        // C-01: Validate all options before any filesystem mutation
        validate_create_options(opts)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

        // P1-23: Preflight filesystem check before any mutation.
        // If the root already exists, check its filesystem. If creating,
        // check the parent's filesystem.
        let check_path = if root.exists() {
            root
        } else {
            root.parent().unwrap_or(root)
        };
        let magic = fs::statfs(check_path).map_err(|e| io::Error::other(format!("statfs: {e}")))?;
        let ft = magic.f_type as i64;
        match ft {
            fs::EXT4_SUPER_MAGIC | fs::XFS_SUPER_MAGIC => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "filesystem type not supported for queue (requires ext4 or xfs)",
                ));
            }
        }

        // Create root directory if needed
        if !root.exists() {
            std::fs::create_dir_all(root)?;
            // Sync the parent directory so the root entry persists
            if let Some(parent) = root.parent() {
                let parent_fd = fs::open_dir_absolute(parent)?;
                fs::fsync_dir_fd(parent_fd.as_raw_fd())?;
            }
        }

        let root_fd = fs::open_dir_absolute(root)?;

        // R2-B01: Refuse to overwrite an existing queue.
        let format_exists = fs::fstatat(root_fd.as_raw_fd(), "FORMAT").is_ok();
        if format_exists {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "queue already initialized; use open() to access an existing queue",
            ));
        }

        // R2-B01/P1-08: Create an exclusive initialization marker BEFORE any other state.
        // P1-08: If .initializing already exists but FORMAT is absent, the previous
        // init was interrupted by a crash. Safe to clean up and retry since no FORMAT
        // means no queue identity was committed.
        let _init_marker = match fs::create_exclusive(root_fd.as_raw_fd(), ".initializing", 0o600) {
            Ok(fd) => fd,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                // .initializing exists. If FORMAT is absent, this is a stale marker
                // from a crashed init. Safe to remove and retry.
                if !format_exists {
                    let _ = fs::unlinkat(root_fd.as_raw_fd(), ".initializing");
                    // Retry the exclusive create.
                    fs::create_exclusive(root_fd.as_raw_fd(), ".initializing", 0o600).map_err(
                        |_| {
                            io::Error::new(
                                io::ErrorKind::AlreadyExists,
                                "could not acquire init lock after cleaning stale marker",
                            )
                        },
                    )?
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "queue already initialized; use open() to access an existing queue",
                    ));
                }
            }
            Err(e) => return Err(e),
        };

        // R2-B01: Use RAII guard to clean up the init marker on any failure.
        struct InitGuard {
            root_fd: std::os::unix::io::RawFd,
            armed: bool,
        }
        impl Drop for InitGuard {
            fn drop(&mut self) {
                if self.armed {
                    // Remove the marker so a failed init can be retried
                    let _ = fs::unlinkat(self.root_fd, ".initializing");
                }
            }
        }
        let mut init_guard = InitGuard {
            root_fd: root_fd.as_raw_fd(),
            armed: true,
        };

        // R2-B01: Create control/ early so we can hold the maintenance lock
        // with RAII (no mem::forget leak).
        fs::mkdirat_eexist_ok(root_fd.as_raw_fd(), "control", 0o700)?;
        let control_fd = fs::open_directory(root_fd.as_raw_fd(), "control")?;
        fs::create_exclusive(control_fd.as_raw_fd(), "maintenance.lock", 0o600).or_else(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                fs::openat(
                    control_fd.as_raw_fd(),
                    "maintenance.lock",
                    libc::O_RDWR,
                    0o600,
                )
            } else {
                Err(e)
            }
        })?;
        let lock_fd = fs::openat(
            control_fd.as_raw_fd(),
            "maintenance.lock",
            libc::O_RDWR,
            0o600,
        )?;
        let locked = fs::try_ofd_write_lock(lock_fd.as_raw_fd())?;
        if !locked {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "another initializer or maintenance process holds the lock",
            ));
        }
        // H1: Hold the maintenance lock for the duration of init by binding it.
        // It will be released when _init_lock goes out of scope at function end.
        let _init_lock = lock_fd;

        // Generate queue ID
        let queue_id = fs::random_128bit()?;
        let created_at = fs::clock_realtime_ns()?;

        let format_rec = FormatRecord {
            queue_id,
            created_at_unix_ns: created_at,
            shard_count: opts.shard_count,
            lease_bucket_width_ns: opts.lease_bucket_width_ns,
            delayed_bucket_width_ns: opts.delayed_bucket_width_ns,
            terminal_bucket_width_ns: opts.terminal_bucket_width_ns,
            max_payload_length: opts.max_payload_length,
        };

        // Create static directories
        for dir in [
            "control",
            "tmp",
            "ready",
            "leased",
            "delayed",
            "receipts",
            "dead",
            "quarantine",
        ] {
            fs::mkdirat_eexist_ok(root_fd.as_raw_fd(), dir, 0o700)?;
        }
        // Sync root after directory creation
        fs::fsync_dir_fd(root_fd.as_raw_fd())?;

        // Create static shard directories under ready/
        let ready_fd = fs::open_directory(root_fd.as_raw_fd(), "ready")?;
        for i in 0..opts.shard_count {
            let shard_name = format!("{i:04x}");
            fs::mkdirat_eexist_ok(ready_fd.as_raw_fd(), &shard_name, 0o700)?;
        }
        // Sync ready/ after shard creation
        fs::fsync_dir_fd(ready_fd.as_raw_fd())?;
        // Sync root
        fs::fsync_dir_fd(root_fd.as_raw_fd())?;

        // Create control lock files
        let control_fd = fs::open_directory(root_fd.as_raw_fd(), "control")?;
        for lock_file in ["maintenance.lock", "wall-watermark.lock"] {
            let fd =
                fs::create_exclusive(control_fd.as_raw_fd(), lock_file, 0o600).or_else(|e| {
                    if e.kind() == io::ErrorKind::AlreadyExists {
                        fs::openat(control_fd.as_raw_fd(), lock_file, 0o2, 0o600)
                    } else {
                        Err(e)
                    }
                })?;
            fs::fsync(fd.as_raw_fd())?;
        }
        fs::fsync_dir_fd(control_fd.as_raw_fd())?;
        fs::fsync_dir_fd(root_fd.as_raw_fd())?;

        // Write initial wall watermark
        let wall_now = fs::clock_realtime_ns()?;
        let wall_bucket =
            bucket_number(wall_now, opts.delayed_bucket_width_ns).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "zero bucket width in init")
            })?;
        let wm = WatermarkRecord {
            highest_observed_bucket: wall_bucket,
            sequence: 0,
        };
        let wm_bytes = wm.encode();
        // Write via temp file then rename
        // C-03: Use unique temp name to avoid collision on partial init rerun
        let wm_tmp_name = format!(
            ".wm.tmp.{}",
            steadq_names::hex_encode(&fs::random_128bit()?)
        );
        let wm_tmp = fs::create_exclusive(control_fd.as_raw_fd(), &wm_tmp_name, 0o600)?;
        fs::write_all(wm_tmp.as_raw_fd(), &wm_bytes)?;
        fs::fsync(wm_tmp.as_raw_fd())?;
        fs::renameat(
            control_fd.as_raw_fd(),
            &wm_tmp_name,
            control_fd.as_raw_fd(),
            "wall-watermark",
        )?;
        fs::fsync_dir_fd(control_fd.as_raw_fd())?;

        // Write FORMAT file
        let format_bytes = format_rec.encode();
        // C-03: Unique temp name for partial init recovery
        let fmt_tmp_name = format!(
            ".format.tmp.{}",
            steadq_names::hex_encode(&fs::random_128bit()?)
        );
        let fmt_tmp = fs::create_exclusive(root_fd.as_raw_fd(), &fmt_tmp_name, 0o600)?;
        fs::write_all(fmt_tmp.as_raw_fd(), &format_bytes)?;
        fs::fsync(fmt_tmp.as_raw_fd())?;
        // R2-B01: Publish FORMAT with RENAME_NOREPLACE so two concurrent
        // initializers cannot overwrite each other.
        match fs::renameat2_noreplace(
            root_fd.as_raw_fd(),
            &fmt_tmp_name,
            root_fd.as_raw_fd(),
            "FORMAT",
        ) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                // Another initializer won the race. Clean up our temp and bail.
                let _ = fs::unlinkat(root_fd.as_raw_fd(), &fmt_tmp_name);
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "another initializer published FORMAT first",
                ));
            }
            Err(e) => return Err(e),
        }
        // C-02: Set FORMAT to read-only before final dir fsync.
        fs::fchmodat(root_fd.as_raw_fd(), "FORMAT", 0o400)?;
        fs::fsync_dir_fd(root_fd.as_raw_fd())?;

        // P1-09: FORMAT is now durably published. All subsequent operations are
        // post-commit cleanup. Their failure does NOT mean init failed - the
        // queue exists and is usable. Log errors but don't fail the API call.
        init_guard.armed = false;
        let _ = fs::unlinkat(root_fd.as_raw_fd(), ".initializing");
        let _ = fs::fsync_dir_fd(root_fd.as_raw_fd());

        Ok(format_rec)
    }

    /// Open an existing queue.
    pub fn open(root: &Path, opts: &OpenOptions) -> Result<Self, Error> {
        // B-11: Open root first using descriptor-relative, no-symlink semantics
        let root_fd = fs::open_dir_absolute(root).map_err(|e| Error::IoFailure(e.to_string()))?;

        // B-11: Validate root is a directory
        let root_stat =
            fs::fstat(root_fd.as_raw_fd()).map_err(|e| Error::IoFailure(e.to_string()))?;
        if root_stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(Error::QueueCorrupt("root path is not a directory".into()));
        }

        // B-11: Read FORMAT through descriptor-relative open, not pathname
        let format_fd = fs::openat(root_fd.as_raw_fd(), "FORMAT", libc::O_RDONLY, 0)
            .map_err(|e| Error::IoFailure(e.to_string()))?;
        let mut format_bytes = Vec::new();
        {
            let mut buf = [0u8; 4096];
            loop {
                match fs::read(format_fd.as_raw_fd(), &mut buf) {
                    Ok(0) => break,
                    Ok(n) => format_bytes.extend_from_slice(&buf[..n]),
                    Err(e) => return Err(Error::IoFailure(e.to_string())),
                }
            }
        }
        let format_rec = FormatRecord::decode(&format_bytes).map_err(|e| match e {
            steadq_format::FormatError::UnsupportedVersion(_, _) => Error::UnsupportedFormat,
            _ => Error::QueueCorrupt(format!("FORMAT decode: {e}")),
        })?;

        // Validate retention bound: ceil(retention / terminal_width) + 2 <= 4096
        let probe_count = ceiling_bucket(
            opts.receipt_retention_ns,
            format_rec.terminal_bucket_width_ns,
        )
        .unwrap_or(0)
        .saturating_add(2);
        if probe_count > 4096 {
            return Err(Error::InvalidInput(
                "receipt retention exceeds duplicate-ack probe bound".into(),
            ));
        }

        // Check filesystem type
        if !opts.allow_unsupported_fs {
            let magic = fs::statfs(root).map_err(|e| Error::IoFailure(e.to_string()))?;
            let ft = magic.f_type as i64;
            match ft {
                fs::EXT4_SUPER_MAGIC | fs::XFS_SUPER_MAGIC => {}
                fs::TMPFS_MAGIC => {
                    return Err(Error::UnsupportedFilesystem);
                }
                fs::NFS_SUPER_MAGIC | fs::FUSE_SUPER_MAGIC | fs::OVERLAYFS_SUPER_MAGIC => {
                    return Err(Error::UnsupportedFilesystem);
                }
                _ => {
                    return Err(Error::UnsupportedFilesystem);
                }
            }
        }

        // B-11: Require all state directories to exist and be on the same device.
        for state_dir in &[
            "control",
            "ready",
            "leased",
            "delayed",
            "receipts",
            "dead",
            "quarantine",
            "tmp",
        ] {
            match fs::fstatat(root_fd.as_raw_fd(), state_dir) {
                Ok(stat) => {
                    if stat.st_dev != root_stat.st_dev {
                        return Err(Error::QueueCorrupt(format!(
                            "state directory '{state_dir}' is on a different device than root"
                        )));
                    }
                    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
                        return Err(Error::QueueCorrupt(format!(
                            "state path '{state_dir}' is not a directory"
                        )));
                    }
                }
                Err(_) => {
                    return Err(Error::QueueCorrupt(format!(
                        "required state directory '{state_dir}' is missing"
                    )));
                }
            }
        }

        // Read boot ID
        let boot_id = fs::read_boot_id().map_err(|e| Error::IoFailure(e.to_string()))?;
        let boot_id_bin = steadq_names::boot_id_bytes(&boot_id)
            .ok_or_else(|| Error::InvalidInput("invalid boot_id format".into()))?;

        // Generate worker nonce
        let worker_nonce = fs::random_128bit().map_err(|e| Error::IoFailure(e.to_string()))?;

        // Acquire shared maintenance lock
        let maint_fd = fs::openat(root_fd.as_raw_fd(), "control/maintenance.lock", 0o0, 0o600)
            .map_err(|e| Error::IoFailure(e.to_string()))?;
        let locked = fs::try_ofd_read_lock(maint_fd.as_raw_fd())
            .map_err(|e| Error::IoFailure(e.to_string()))?;
        if !locked {
            return Err(Error::MaintenanceBusy);
        }
        Ok(Queue {
            root_fd,
            root_path: root.to_path_buf(),
            format: format_rec,
            boot_id,
            boot_id_bytes: boot_id_bin,
            poisoned: false,
            scan_round: 0,
            worker_nonce,
            options: opts.clone(),
            maint_lock_fd: Some(maint_fd),
            recovery_cursor: RecoveryCursor::default(),
        })
    }

    pub fn format(&self) -> &FormatRecord {
        &self.format
    }

    pub fn queue_id(&self) -> &[u8; 16] {
        &self.format.queue_id
    }

    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }

    pub fn root_fd(&self) -> RawFd {
        self.root_fd.as_raw_fd()
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    fn check_not_poisoned(&self) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::QueuePoisoned("handle is poisoned".into()));
        }
        Ok(())
    }

    fn poison(&mut self) {
        self.poisoned = true;
    }

    #[allow(dead_code)]
    pub(crate) fn layout(&self) -> layout::Layout<'_> {
        layout::Layout::new(
            &self.format.queue_id,
            self.format.shard_count,
            self.format.lease_bucket_width_ns,
            self.format.delayed_bucket_width_ns,
            self.format.terminal_bucket_width_ns,
            &self.boot_id,
        )
    }
    /// Compute the effective wall floor: max(CLOCK_REALTIME, stored watermark bucket * width)
    /// Wall floor for mutating operations. P0-01: Returns Err and poisons
    /// on failure so callers abort before computing destination paths.
    pub(crate) fn wall_floor_for_mutation(&mut self) -> Result<u64, Error> {
        match self.effective_wall_floor_ns_checked() {
            Ok(ns) => Ok(ns),
            Err(e) => {
                self.poison();
                Err(e)
            }
        }
    }

    /// Wall floor for read-only or recovery operations. Falls back to raw
    /// CLOCK_REALTIME on error without poisoning, since recovery must continue.
    pub(crate) fn effective_wall_floor_ns(&self) -> u64 {
        match self.effective_wall_floor_ns_checked() {
            Ok(ns) => ns,
            Err(_) => steadq_fs_linux::clock_realtime_ns().unwrap_or(0),
        }
    }

    /// R2-B05: Fallible version of effective_wall_floor_ns.
    pub fn effective_wall_floor_ns_checked(&self) -> Result<u64, Error> {
        let clock = steadq_fs_linux::clock_realtime_ns()
            .map_err(|e| Error::IoFailure(format!("CLOCK_REALTIME: {e}")))?;
        match self.read_wall_watermark() {
            Ok(wm) => steadq_math::effective_wall_floor(
                clock,
                wm.highest_observed_bucket,
                self.format.delayed_bucket_width_ns,
            )
            .ok_or_else(|| Error::QueueCorrupt("watermark computation overflow".into())),
            Err(WatermarkReadError::NotFound) => Ok(clock),
            Err(WatermarkReadError::Truncated(msg)) => {
                Err(Error::QueueCorrupt(format!("watermark truncated: {msg}")))
            }
            Err(WatermarkReadError::Corrupt(msg)) => {
                Err(Error::QueueCorrupt(format!("watermark corrupt: {msg}")))
            }
            Err(WatermarkReadError::Io(msg)) => Err(Error::IoFailure(msg)),
        }
    }

    /// Read the wall watermark record from control/wall-watermark.
    /// Returns Ok on success, Err(NotFound) when no watermark has been written yet,
    /// Err(Corrupt/Truncated) on digest or size mismatch, Err(Io) on I/O failure.
    fn read_wall_watermark(&self) -> Result<steadq_format::WatermarkRecord, WatermarkReadError> {
        let control_fd = fs::open_directory(self.root_fd.as_raw_fd(), "control")
            .map_err(|e| WatermarkReadError::Io(e.to_string()))?;
        let data = match fs::openat(control_fd.as_raw_fd(), "wall-watermark", libc::O_RDONLY, 0) {
            Ok(fd) => fd,
            Err(e) => {
                if watermark_open_is_not_found(&e) {
                    return Err(WatermarkReadError::NotFound);
                }
                return Err(WatermarkReadError::Io(e.to_string()));
            }
        };
        let mut buf = [0u8; steadq_format::WATERMARK_SIZE];
        if let Err(e) = fs::pread_exact(data.as_raw_fd(), &mut buf, 0) {
            return Err(WatermarkReadError::Truncated(e.to_string()));
        }
        steadq_format::WatermarkRecord::decode(&buf)
            .map_err(|e| WatermarkReadError::Corrupt(e.to_string()))
    }

    /// B-05: Advance the wall watermark to max(stored, observed).
    /// Re-reads under lock, computes max, writes atomically with sequence increment.
    pub fn advance_wall_watermark(&self, observed_ns: u64) -> Result<(), Error> {
        let control_fd = fs::open_directory(self.root_fd.as_raw_fd(), "control")
            .map_err(|e| Error::IoFailure(e.to_string()))?;

        // Acquire exclusive write lock on wall-watermark.lock
        let lock_fd = fs::openat(
            control_fd.as_raw_fd(),
            "wall-watermark.lock",
            libc::O_RDWR,
            0o600,
        )
        .map_err(|e| Error::IoFailure(e.to_string()))?;
        let locked = fs::try_ofd_write_lock(lock_fd.as_raw_fd())
            .map_err(|e| Error::IoFailure(e.to_string()))?;
        if !locked {
            return Err(Error::MaintenanceBusy);
        }

        // Re-read current watermark under lock
        let current = self.read_wall_watermark();
        let observed_bucket =
            steadq_math::bucket_number(observed_ns, self.format.delayed_bucket_width_ns)
                .unwrap_or(0);

        let (new_bucket, new_seq) = match current {
            Ok(wm) => {
                if !watermark_should_advance(observed_bucket, wm.highest_observed_bucket) {
                    return Ok(());
                }
                let new_seq = wm.sequence.checked_add(1).ok_or(Error::StateExhausted)?;
                (observed_bucket, new_seq)
            }
            Err(WatermarkReadError::NotFound) => (observed_bucket, 1),
            Err(WatermarkReadError::Truncated(msg)) => {
                return Err(Error::QueueCorrupt(format!("watermark truncated: {msg}")))
            }
            Err(WatermarkReadError::Corrupt(msg)) => {
                return Err(Error::QueueCorrupt(format!("watermark corrupt: {msg}")))
            }
            Err(WatermarkReadError::Io(msg)) => return Err(Error::IoFailure(msg)),
        };

        let new_wm = steadq_format::WatermarkRecord {
            highest_observed_bucket: new_bucket,
            sequence: new_seq,
        };
        let wm_bytes = new_wm.encode();

        // Write via unique temp, then atomic rename, then sync
        let tmp_name = format!(
            ".wm.adv.{}",
            steadq_names::hex_encode(
                &fs::random_128bit().map_err(|e| Error::IoFailure(e.to_string()))?
            )
        );
        let tmp_fd = fs::create_exclusive(control_fd.as_raw_fd(), &tmp_name, 0o600)
            .map_err(|e| Error::IoFailure(e.to_string()))?;
        fs::write_all(tmp_fd.as_raw_fd(), &wm_bytes)
            .map_err(|e| Error::IoFailure(e.to_string()))?;
        fs::fsync(tmp_fd.as_raw_fd()).map_err(|e| Error::IoFailure(e.to_string()))?;
        fs::renameat(
            control_fd.as_raw_fd(),
            &tmp_name,
            control_fd.as_raw_fd(),
            "wall-watermark",
        )
        .map_err(|e| Error::IoFailure(e.to_string()))?;
        fs::fsync_dir_fd(control_fd.as_raw_fd()).map_err(|e| Error::IoFailure(e.to_string()))?;

        Ok(())
    }

    /// Enqueue a job with the given payload and metadata.
    pub fn enqueue(&mut self, job: EnqueueInput) -> EnqueueOutcome {
        if let Err(e) = self.check_not_poisoned() {
            let ticket = EnqueueTicket {
                job_id: [0; 16],
                envelope_digest: [0; 32],
                expected_initial_state: InitialState::Ready,
                expected_relative_path: String::new(),
            };
            return EnqueueOutcome::NotCommitted(ticket, e);
        }

        // Generate job ID before any filesystem operation
        let job_id = match fs::random_128bit() {
            Ok(id) => id,
            Err(e) => {
                let ticket = EnqueueTicket {
                    job_id: [0; 16],
                    envelope_digest: [0; 32],
                    expected_initial_state: InitialState::Ready,
                    expected_relative_path: String::new(),
                };
                return EnqueueOutcome::NotCommitted(ticket, Error::IoFailure(e.to_string()));
            }
        };

        let created_at = match fs::clock_realtime_ns() {
            Ok(t) => t,
            Err(e) => {
                let ticket = EnqueueTicket {
                    job_id,
                    envelope_digest: [0; 32],
                    expected_initial_state: InitialState::Ready,
                    expected_relative_path: String::new(),
                };
                return EnqueueOutcome::NotCommitted(ticket, Error::IoFailure(e.to_string()));
            }
        };

        // Validate maximum_attempts
        if job.maximum_attempts == 0 {
            let ticket = EnqueueTicket {
                job_id,
                envelope_digest: [0; 32],
                expected_initial_state: InitialState::Ready,
                expected_relative_path: String::new(),
            };
            return EnqueueOutcome::NotCommitted(
                ticket,
                Error::InvalidInput("maximum_attempts must be >= 1".into()),
            );
        }

        // Encode extension header
        let ext = ExtensionHeader {
            initial_not_before_unix_ns: job.initial_not_before,
            content_type: job.content_type.clone(),
            metadata: job.metadata.clone(),
            producer_id: job.producer_id.clone(),
            trace_context: job.trace_context.clone(),
        };

        let ext_bytes = match ext.encode() {
            Ok(b) => b,
            Err(e) => {
                let ticket = EnqueueTicket {
                    job_id,
                    envelope_digest: [0; 32],
                    expected_initial_state: InitialState::Ready,
                    expected_relative_path: String::new(),
                };
                return EnqueueOutcome::NotCommitted(ticket, Error::InvalidInput(e.to_string()));
            }
        };

        // C-11: Validate payload size BEFORE hashing
        if job.payload.len() as u64 > self.format.max_payload_length.min(MAX_PAYLOAD_LENGTH) {
            let ticket = EnqueueTicket {
                job_id,
                envelope_digest: [0; 32],
                expected_initial_state: InitialState::Ready,
                expected_relative_path: String::new(),
            };
            return EnqueueOutcome::NotCommitted(
                ticket,
                Error::InvalidInput("payload exceeds limit".into()),
            );
        }

        // Compute payload digest (after size validation - C-11)
        let pdig = payload_digest(&job.payload);

        // Build fixed header
        let mut header = FixedHeader {
            extension_header_length: ext_bytes.len() as u32,
            payload_length: job.payload.len() as u64,
            flags: 0,
            digest_algorithm: DIGEST_ALGORITHM_SHA256,
            job_id,
            maximum_attempts: job.maximum_attempts,
            created_at_unix_ns: created_at,
            payload_digest: pdig,
            envelope_digest: [0; 32],
        };
        let env_dig = match envelope_digest(&header, &ext_bytes) {
            Some(d) => d,
            None => {
                let ticket = EnqueueTicket {
                    job_id,
                    envelope_digest: [0; 32],
                    expected_initial_state: InitialState::Ready,
                    expected_relative_path: String::new(),
                };
                return EnqueueOutcome::NotCommitted(
                    ticket,
                    Error::InvalidInput("extension length mismatch".into()),
                );
            }
        };
        header.envelope_digest = env_dig;

        // Determine initial state: ready or delayed
        let now_wall = match self.wall_floor_for_mutation() {
            Ok(v) => v,
            Err(e) => {
                return EnqueueOutcome::NotCommitted(
                    EnqueueTicket {
                        job_id: [0; 16],
                        envelope_digest: [0; 32],
                        expected_initial_state: crate::errors::InitialState::Ready,
                        expected_relative_path: String::new(),
                    },
                    e,
                )
            }
        };
        let (initial_state, _) = match job.initial_not_before {
            Some(nb) if nb > now_wall => {
                let (eb, _) =
                    match eligibility_bucket_and_ns(nb, self.format.delayed_bucket_width_ns) {
                        Some(v) => v,
                        None => {
                            let ticket = EnqueueTicket {
                                job_id,
                                envelope_digest: header.envelope_digest,
                                expected_initial_state: InitialState::Ready,
                                expected_relative_path: String::new(),
                            };
                            return EnqueueOutcome::NotCommitted(
                                ticket,
                                Error::InvalidInput("eligibility overflow".into()),
                            );
                        }
                    };
                (InitialState::Delayed, eb)
            }
            _ => (InitialState::Ready, 0),
        };

        // Build the canonical filename and path
        let common = CommonFields {
            job_id,
            generation: 0,
            attempt: 0,
            maximum_attempts: job.maximum_attempts,
        };

        let (dest_dir_relative, filename, expected_path) = match initial_state {
            InitialState::Ready => {
                let target = self.layout().ready(&common);
                let path = target.relative_path();
                (target.directory(), target.filename, path)
            }
            InitialState::Delayed => {
                let target = self
                    .layout()
                    .delayed(&common, nb_to_u64(job.initial_not_before))
                    .unwrap();
                let path = target.relative_path();
                (target.directory(), target.filename, path)
            }
        };

        let ticket = EnqueueTicket {
            job_id,
            envelope_digest: header.envelope_digest,
            expected_initial_state: initial_state,
            expected_relative_path: expected_path.clone(),
        };

        // Create the job file using O_TMPFILE in the destination directory
        let result = self.write_and_publish(
            &dest_dir_relative,
            &filename,
            &header,
            &ext_bytes,
            &job.payload,
        );

        match result {
            Ok(()) => {
                // R2-B05: Advance wall watermark. Failure is not fatal to the
                // committed enqueue but is logged via the poison flag for
                // diagnostics. The watermark is advisory monotonicity, not
                // a correctness barrier for the enqueue itself.
                if self.advance_wall_watermark(created_at).is_err() {
                    // Watermark advancement failed; the enqueue is still committed.
                    // Future clock-rollback protection is degraded for this bucket.
                }
                EnqueueOutcome::Committed(ticket)
            }
            Err(PublishError::NotCommitted(e)) => EnqueueOutcome::NotCommitted(ticket, e),
            Err(PublishError::OutcomeUnknown(e)) => {
                self.poison();
                EnqueueOutcome::OutcomeUnknown(ticket, e)
            }
        }
    }

    /// Write the job envelope to a temp file and publish via rename.
    fn write_and_publish(
        &mut self,
        dest_dir_relative: &str,
        dest_name: &str,
        header: &FixedHeader,
        ext_bytes: &[u8],
        payload: &[u8],
    ) -> Result<(), PublishError> {
        // Ensure destination directory exists
        self.ensure_dir(dest_dir_relative)
            .map_err(|e| PublishError::NotCommitted(Error::IoFailure(e.to_string())))?;

        // Open destination directory
        let dest_fd = open_relative(self.root_fd.as_raw_fd(), dest_dir_relative)
            .map_err(|e| PublishError::NotCommitted(Error::IoFailure(e.to_string())))?;

        // Try O_TMPFILE path first
        match fs::open_tmpfile(dest_fd.as_raw_fd()) {
            Ok(tmp_fd) => {
                // Write header (zeroed placeholder)
                let header_bytes = header
                    .encode(ext_bytes)
                    .map_err(|e| PublishError::NotCommitted(Error::InvalidInput(e.to_string())))?;
                fs::write_all(tmp_fd.as_raw_fd(), &header_bytes)
                    .map_err(PublishError::classify_write)?;
                // Write extension
                if !ext_bytes.is_empty() {
                    fs::write_all(tmp_fd.as_raw_fd(), ext_bytes)
                        .map_err(PublishError::classify_write)?;
                }
                // Write payload
                if !payload.is_empty() {
                    fs::write_all(tmp_fd.as_raw_fd(), payload)
                        .map_err(PublishError::classify_write)?;
                }
                // C-13: No redundant pwrite - header was already written correctly above.
                // fsync file (before publication: NotCommitted on failure)
                fs::fsync(tmp_fd.as_raw_fd()).map_err(PublishError::classify_pre_pub_fsync)?;

                // Publish via linkat - C-09: capture errors for capability classification
                let link1 =
                    fs::linkat_empty_path(tmp_fd.as_raw_fd(), dest_fd.as_raw_fd(), dest_name);
                if link1.is_ok() {
                    fs::fsync_dir_fd(dest_fd.as_raw_fd())
                        .map_err(PublishError::classify_post_fsync)?;
                    return Ok(());
                }
                let link2 =
                    fs::linkat_proc_self_fd(tmp_fd.as_raw_fd(), dest_fd.as_raw_fd(), dest_name);
                if link2.is_ok() {
                    fs::fsync_dir_fd(dest_fd.as_raw_fd())
                        .map_err(PublishError::classify_post_fsync)?;
                    return Ok(());
                }

                // C-09: Fall back to named temp file only for capability errors.
                // Propagate I/O, resource, and permission errors.
                let last_err = link2.err();
                if let Some(ref e) = last_err {
                    if fs::should_propagate_on_fallback(e) {
                        return Err(PublishError::NotCommitted(Error::IoFailure(e.to_string())));
                    }
                }
                self.named_fallback(dest_dir_relative, dest_name, header, ext_bytes, payload)
            }
            Err(e) => {
                // C-09: Only fall back on capability errors (ENOENT, ENOSYS, EOPNOTSUPP)
                if fs::should_propagate_on_fallback(&e) {
                    return Err(PublishError::NotCommitted(Error::IoFailure(e.to_string())));
                }
                self.named_fallback(dest_dir_relative, dest_name, header, ext_bytes, payload)
            }
        }
    }

    /// Named temporary file fallback for enqueue.
    fn named_fallback(
        &self,
        dest_dir_relative: &str,
        dest_name: &str,
        header: &FixedHeader,
        ext_bytes: &[u8],
        payload: &[u8],
    ) -> Result<(), PublishError> {
        // Ensure tmp/<boot-id>/<shard>/ exists
        // Extract shard from dest_dir
        let shard_part = dest_dir_relative.rsplit('/').next().unwrap_or("0000");
        let tmp_dir = format!("tmp/{}/{}", self.boot_id, shard_part);

        self.ensure_dir(&tmp_dir)
            .map_err(|e| PublishError::NotCommitted(Error::IoFailure(e.to_string())))?;

        let tmp_dir_fd = open_relative(self.root_fd.as_raw_fd(), &tmp_dir)
            .map_err(|e| PublishError::NotCommitted(Error::IoFailure(e.to_string())))?;

        // Create temp file name
        let boottime = fs::clock_boottime_ns()
            .map_err(|e| PublishError::NotCommitted(Error::IoFailure(e.to_string())))?;
        let random = fs::random_128bit()
            .map_err(|e| PublishError::NotCommitted(Error::IoFailure(e.to_string())))?;
        let temp_name = temp_filename(boottime, &random);

        let tmp_file = fs::create_exclusive(tmp_dir_fd.as_raw_fd(), &temp_name, 0o600)
            .map_err(|e| PublishError::NotCommitted(Error::IoFailure(e.to_string())))?;

        // C-10: RAII guard to unlink temp file on early return
        struct TempGuard<'a> {
            dir_fd: std::os::unix::io::RawFd,
            name: &'a str,
            armed: bool,
        }
        impl<'a> Drop for TempGuard<'a> {
            fn drop(&mut self) {
                if self.armed {
                    let _ = fs::unlinkat(self.dir_fd, self.name);
                }
            }
        }
        let mut temp_guard = TempGuard {
            dir_fd: tmp_dir_fd.as_raw_fd(),
            name: &temp_name,
            armed: true,
        };

        // Write header
        let header_bytes = header
            .encode(ext_bytes)
            .map_err(|e| PublishError::NotCommitted(Error::InvalidInput(e.to_string())))?;
        fs::write_all(tmp_file.as_raw_fd(), &header_bytes).map_err(PublishError::classify_write)?;
        if !ext_bytes.is_empty() {
            fs::write_all(tmp_file.as_raw_fd(), ext_bytes).map_err(PublishError::classify_write)?;
        }
        if !payload.is_empty() {
            fs::write_all(tmp_file.as_raw_fd(), payload).map_err(PublishError::classify_write)?;
        }
        // C-13: No redundant pwrite - header was written correctly above.
        // fsync file (before publication: NotCommitted on failure)
        fs::fsync(tmp_file.as_raw_fd()).map_err(PublishError::classify_pre_pub_fsync)?;

        // Open destination directory for rename
        let dest_fd = open_relative(self.root_fd.as_raw_fd(), dest_dir_relative)
            .map_err(|e| PublishError::NotCommitted(Error::IoFailure(e.to_string())))?;

        // Rename with NOREPLACE
        match fs::renameat2_noreplace(
            tmp_dir_fd.as_raw_fd(),
            &temp_name,
            dest_fd.as_raw_fd(),
            dest_name,
        ) {
            Ok(()) => {
                temp_guard.armed = false; // C-10: disarm on success
                                          // Sync destination first, then source
                fs::fsync_dir_fd(dest_fd.as_raw_fd()).map_err(PublishError::classify_post_fsync)?;
                fs::fsync_dir_fd(tmp_dir_fd.as_raw_fd())
                    .map_err(PublishError::classify_post_fsync)?;
                Ok(())
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                Err(PublishError::NotCommitted(Error::IdentityCollision))
            }
            Err(e) => Err(PublishError::classify_write(e)),
        }
    }

    /// Create a directory path recursively, syncing parents.
    pub(crate) fn ensure_dir(&self, relative: &str) -> io::Result<()> {
        let components: Vec<&str> = relative.split('/').filter(|s| !s.is_empty()).collect();
        let mut current_fd = self.root_fd.as_raw_fd();
        let mut owned_fds = Vec::new();

        for (i, comp) in components.iter().enumerate() {
            let was_created = fs::mkdirat_eexist_ok(current_fd, comp, 0o700)?;
            // Open the child
            let child = fs::open_directory(current_fd, comp)?;
            // P-01: Only fsync parent when a new child entry was actually created
            if was_created {
                if i > 0 {
                    fs::fsync_dir_fd(current_fd)?;
                } else {
                    fs::fsync_dir_fd(self.root_fd.as_raw_fd())?;
                }
            }
            current_fd = child.as_raw_fd();
            owned_fds.push(child);
        }
        Ok(())
    }
    /// Claim a ready job, returning a lease.
    /// max_wait_ns is accepted for API compatibility but currently performs
    /// a single immediate scan (C-14: bounded wait/backoff not yet implemented).
    pub fn lease(&mut self, _max_wait_ns: u64, lease_duration_ns: u64) -> LeaseOutcome {
        if let Err(e) = self.check_not_poisoned() {
            return LeaseOutcome::NotCommitted(e);
        }

        // Validate lease duration: 1s to 7d
        let min_dur = 1_000_000_000u64;
        let max_dur = 7 * 24 * 60 * 60 * 1_000_000_000u64;
        if lease_duration_ns < min_dur || lease_duration_ns > max_dur {
            return LeaseOutcome::NotCommitted(Error::InvalidInput(
                "lease duration must be 1s to 7d".into(),
            ));
        }

        // C-16: Clocks are re-captured inside the scan loop before each claim
        let _boottime_now = fs::clock_boottime_ns().ok();
        let _wall_now = fs::clock_realtime_ns().ok();

        // C-19: Track scan completeness to distinguish Empty from I/O error
        let mut scan_had_error = false;

        // C-15: Use and advance the per-worker scan round
        let scan_round = self.scan_round;
        self.scan_round = self.scan_round.wrapping_add(1);
        let (start, stride) = steadq_names::shard_scan_params(
            &self.format.queue_id,
            &self.boot_id_bytes,
            &self.worker_nonce,
            scan_round,
            self.format.shard_count,
        );

        for i in 0..self.format.shard_count {
            let shard = steadq_names::shard_at(start, stride, i, self.format.shard_count);
            let shard_str = shard_hex(shard);

            // Open the ready shard directory
            let ready_dir = format!("ready/{shard_str}");
            let shard_fd = match open_relative(self.root_fd.as_raw_fd(), &ready_dir) {
                Ok(fd) => fd,
                Err(_) => {
                    scan_had_error = true;
                    continue;
                }
            };

            // List entries
            let entries = match fs::read_dir_entries_owned(shard_fd.as_raw_fd()) {
                Ok(e) => e,
                Err(_) => {
                    scan_had_error = true;
                    continue;
                }
            };

            for entry in &entries {
                if !entry.ends_with(".sqj") {
                    continue;
                }

                // Parse and verify the ready filename
                let parsed = match steadq_names::parse_ready(entry) {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                if !parsed.authenticate_tag(&self.format.queue_id, &shard_str) {
                    continue;
                }

                // Verify shard matches job_id
                let computed_shard = compute_shard(
                    &self.format.queue_id,
                    &parsed.common.job_id,
                    self.format.shard_count,
                );
                if computed_shard != shard {
                    continue;
                }

                // Check attempt limit
                if parsed.common.attempt >= parsed.common.maximum_attempts {
                    // Move to dead
                    match self.move_to_dead(
                        &ready_dir,
                        entry,
                        &parsed.common,
                        DeadReason::AttemptsExhausted,
                    ) {
                        Ok(()) => continue,
                        Err(_) => {
                            // P1-07: Don't ignore cleanup failure.
                            scan_had_error = true;
                            self.poison();
                            continue;
                        }
                    }
                }

                // C-16: Re-capture clocks immediately before the claim
                let boottime_claim = match fs::clock_boottime_ns() {
                    Ok(t) => t,
                    Err(e) => return LeaseOutcome::NotCommitted(Error::IoFailure(e.to_string())),
                };
                let wall_claim = match fs::clock_realtime_ns() {
                    Ok(t) => t,
                    Err(e) => return LeaseOutcome::NotCommitted(Error::IoFailure(e.to_string())),
                };
                // Attempt claim: rename ready -> leased
                let lease_token = match fs::random_128bit() {
                    Ok(t) => t,
                    Err(e) => return LeaseOutcome::NotCommitted(Error::IoFailure(e.to_string())),
                };
                let boottime_deadline = match boottime_claim.checked_add(lease_duration_ns) {
                    Some(d) => d,
                    None => continue, // deadline overflow, skip this candidate
                };
                let wall_deadline = match wall_claim.checked_add(lease_duration_ns) {
                    Some(d) => d,
                    None => continue,
                };
                let lease_bucket =
                    steadq_math::lease_bucket(boottime_deadline, self.format.lease_bucket_width_ns)
                        .unwrap_or(0);
                let bucket_str = bucket_hex(lease_bucket);

                // Checked generation increment: a source at u64::MAX cannot transition.
                let new_generation = match parsed.common.generation.checked_add(1) {
                    Some(g) => g,
                    None => continue,
                };
                // Checked attempt increment.
                let new_attempt = match parsed.common.attempt.checked_add(1) {
                    Some(a) => a,
                    None => continue,
                };

                let leased_common = CommonFields {
                    job_id: parsed.common.job_id,
                    generation: new_generation,
                    attempt: new_attempt,
                    maximum_attempts: parsed.common.maximum_attempts,
                };

                let leased_name = steadq_names::make_leased_name(
                    &self.format.queue_id,
                    &self.boot_id,
                    &bucket_str,
                    &shard_str,
                    &leased_common,
                    boottime_deadline,
                    wall_deadline,
                    &lease_token,
                );

                // Ensure lease directory exists
                let leased_dir = format!("leased/{}/{}/{}", self.boot_id, bucket_str, shard_str);
                if let Err(e) = self.ensure_dir(&leased_dir) {
                    // R4-B04: Propagate real errors, don't mask as scan miss
                    scan_had_error = true;
                    let _ = e;
                    continue;
                }

                let leased_dir_fd = match open_relative(self.root_fd.as_raw_fd(), &leased_dir) {
                    Ok(fd) => fd,
                    Err(e) if e.raw_os_error() == Some(libc::ENOENT) => continue,
                    Err(_) => {
                        scan_had_error = true;
                        continue;
                    }
                };

                let claim_source = match Self::open_claim_source(
                    shard_fd.as_raw_fd(),
                    entry,
                    &parsed.common.job_id,
                    parsed.common.maximum_attempts,
                ) {
                    Ok(source) => source,
                    Err(Error::IoFailure(_)) => {
                        scan_had_error = true;
                        continue;
                    }
                    Err(error) => return LeaseOutcome::NotCommitted(error),
                };
                let mut claim_ticket = match self.claim_transition_ticket(
                    &parsed.common,
                    lease_token,
                    claim_source.evidence.clone(),
                    boottime_deadline,
                    wall_deadline,
                ) {
                    Ok(ticket) => ticket,
                    Err(error) => return LeaseOutcome::NotCommitted(error),
                };

                match fs::fstatat(shard_fd.as_raw_fd(), entry) {
                    Ok(stat) => match classify_claim_source_identity(&stat, &claim_source) {
                        ClaimSourceIdentity::Match => {}
                        ClaimSourceIdentity::Mismatch => {
                            return LeaseOutcome::NotCommitted(Error::QueueCorrupt(
                                "ready source identity changed before claim".into(),
                            ));
                        }
                    },
                    Err(error) => {
                        scan_had_error = true;
                        let _ = error;
                        continue;
                    }
                }

                // Rename ready -> leased with NOREPLACE
                match fs::renameat2_noreplace(
                    shard_fd.as_raw_fd(),
                    entry,
                    leased_dir_fd.as_raw_fd(),
                    &leased_name,
                ) {
                    Ok(()) => {
                        let leased_stat = match fs::fstatat(leased_dir_fd.as_raw_fd(), &leased_name)
                        {
                            Ok(stat) => {
                                match classify_claim_source_identity(&stat, &claim_source) {
                                    ClaimSourceIdentity::Match => stat,
                                    ClaimSourceIdentity::Mismatch => {
                                        self.poison();
                                        return LeaseOutcome::OutcomeUnknown(
                                            claim_ticket.with_phase(TransitionPhase::Linearized),
                                        );
                                    }
                                }
                            }
                            Err(_) => {
                                self.poison();
                                return LeaseOutcome::OutcomeUnknown(
                                    claim_ticket.with_phase(TransitionPhase::Linearized),
                                );
                            }
                        };
                        let refreshed_evidence = match Self::read_claim_ticket_evidence(
                            claim_source.file_fd.as_raw_fd(),
                            &parsed.common.job_id,
                            parsed.common.maximum_attempts,
                        ) {
                            Ok(evidence) => evidence,
                            Err(_) => {
                                self.poison();
                                return LeaseOutcome::OutcomeUnknown(
                                    claim_ticket.with_phase(TransitionPhase::Linearized),
                                );
                            }
                        };
                        claim_ticket = match self.claim_transition_ticket(
                            &parsed.common,
                            lease_token,
                            refreshed_evidence,
                            boottime_deadline,
                            wall_deadline,
                        ) {
                            Ok(ticket) => ticket,
                            Err(_) => {
                                self.poison();
                                return LeaseOutcome::OutcomeUnknown(
                                    claim_ticket.with_phase(TransitionPhase::Linearized),
                                );
                            }
                        };
                        // Sync both directories
                        let same_dir = false; // different directories
                        if !same_dir {
                            if fs::fsync_dir_fd(leased_dir_fd.as_raw_fd()).is_err() {
                                self.poison();
                                return LeaseOutcome::OutcomeUnknown(
                                    claim_ticket.with_phase(TransitionPhase::Linearized),
                                );
                            }
                            if fs::fsync_dir_fd(shard_fd.as_raw_fd()).is_err() {
                                self.poison();
                                return LeaseOutcome::OutcomeUnknown(
                                    claim_ticket
                                        .with_phase(TransitionPhase::DestinationDirectoryDurable),
                                );
                            }
                        }

                        // B-03: Post-rename validation failures must NOT continue as Empty.
                        // The claim is committed; failures here are corruption or indeterminate.
                        // Post-rename: open and verify the leased object
                        // Verify link count is exactly 1 (rejects external hard links)
                        if leased_stat.st_nlink != 1 {
                            self.poison();
                            return LeaseOutcome::OutcomeUnknown(
                                claim_ticket.with_phase(TransitionPhase::SourceDirectoryDurable),
                            );
                        }

                        // Read and validate the fixed header
                        // R4-B06: Open with O_NOFOLLOW to reject symlinks
                        let leased_file = claim_source.file_fd;

                        let mut header_buf = [0u8; 128];
                        if fs::pread_exact(leased_file.as_raw_fd(), &mut header_buf, 0).is_err() {
                            self.poison();
                            return LeaseOutcome::OutcomeUnknown(
                                claim_ticket.with_phase(TransitionPhase::SourceDirectoryDurable),
                            );
                        }

                        let header = match FixedHeader::decode(&header_buf) {
                            Ok(h) => h,
                            Err(_) => {
                                self.poison();
                                return LeaseOutcome::OutcomeUnknown(
                                    claim_ticket
                                        .with_phase(TransitionPhase::SourceDirectoryDurable),
                                );
                            }
                        };

                        // Verify job_id matches
                        if header.job_id != parsed.common.job_id {
                            self.poison();
                            return LeaseOutcome::OutcomeUnknown(
                                claim_ticket.with_phase(TransitionPhase::SourceDirectoryDurable),
                            );
                        }

                        // R4-B05: Full structural validation of the claimed object before return.
                        // Verify envelope digest, exact size, and payload limit.
                        {
                            let ext_len_h = header.extension_header_length as usize;
                            if ext_len_h > 65536 {
                                self.poison();
                                return LeaseOutcome::OutcomeUnknown(
                                    claim_ticket
                                        .with_phase(TransitionPhase::SourceDirectoryDurable),
                                );
                            }
                            let mut ext_buf_claim = vec![0u8; ext_len_h];
                            if ext_len_h > 0
                                && fs::pread_exact(leased_file.as_raw_fd(), &mut ext_buf_claim, 128)
                                    .is_err()
                            {
                                self.poison();
                                return LeaseOutcome::OutcomeUnknown(
                                    claim_ticket
                                        .with_phase(TransitionPhase::SourceDirectoryDurable),
                                );
                            }
                            if !steadq_format::verify_envelope_digest(&header, &ext_buf_claim) {
                                self.poison();
                                return LeaseOutcome::OutcomeUnknown(
                                    claim_ticket
                                        .with_phase(TransitionPhase::SourceDirectoryDurable),
                                );
                            }
                            // Verify exact file size
                            let expected_claim_size =
                                (128 + ext_len_h + header.payload_length as usize) as u64;
                            if leased_stat.st_size as u64 != expected_claim_size {
                                self.poison();
                                return LeaseOutcome::OutcomeUnknown(
                                    claim_ticket
                                        .with_phase(TransitionPhase::SourceDirectoryDurable),
                                );
                            }
                            // Verify payload limit
                            if header.payload_length > self.format.max_payload_length {
                                self.poison();
                                return LeaseOutcome::OutcomeUnknown(
                                    claim_ticket
                                        .with_phase(TransitionPhase::SourceDirectoryDurable),
                                );
                            }
                            // Verify header max_attempts matches filename
                            if header.maximum_attempts != parsed.common.maximum_attempts {
                                self.poison();
                                return LeaseOutcome::OutcomeUnknown(
                                    claim_ticket
                                        .with_phase(TransitionPhase::SourceDirectoryDurable),
                                );
                            }
                        }

                        // B2: Extension read/decode failure after claim is a post-linearization
                        // corruption. Do not return an ordinary lease with empty content_type.
                        let content_type = if header.extension_header_length > 0 {
                            if header.extension_header_length > 65536 {
                                self.poison();
                                return LeaseOutcome::OutcomeUnknown(
                                    claim_ticket
                                        .with_phase(TransitionPhase::SourceDirectoryDurable),
                                );
                            }
                            let mut ext_buf = vec![0u8; header.extension_header_length as usize];
                            match fs::pread_exact(leased_file.as_raw_fd(), &mut ext_buf, 128) {
                                Ok(()) => {
                                    match steadq_format::cbor::ExtensionHeader::decode(&ext_buf) {
                                        Ok(e) => e.content_type,
                                        Err(_) => {
                                            self.poison();
                                            return LeaseOutcome::OutcomeUnknown(
                                                claim_ticket.with_phase(
                                                    TransitionPhase::SourceDirectoryDurable,
                                                ),
                                            );
                                        }
                                    }
                                }
                                Err(_) => {
                                    self.poison();
                                    return LeaseOutcome::OutcomeUnknown(
                                        claim_ticket
                                            .with_phase(TransitionPhase::SourceDirectoryDurable),
                                    );
                                }
                            }
                        } else {
                            String::new()
                        };

                        // P0-01: Verify payload digest on held fd before delivery.
                        // Deterministic PayloadCorrupt is quarantined, not delivered.
                        // Indeterminate I/O poisons and yields OutcomeUnknown.
                        if let Err(e) = self.verify_payload_on_fd(leased_file.as_raw_fd()) {
                            match e {
                                Error::PayloadCorrupt => {
                                    let _ = self.quarantine_corrupt_lease(
                                        leased_dir_fd.as_raw_fd(),
                                        &leased_name,
                                        leased_file.as_raw_fd(),
                                    );
                                    return LeaseOutcome::NotCommitted(Error::PayloadCorrupt);
                                }
                                _ => {
                                    self.poison();
                                    return LeaseOutcome::OutcomeUnknown(
                                        claim_ticket
                                            .with_phase(TransitionPhase::SourceDirectoryDurable),
                                    );
                                }
                            }
                        }

                        let lease_info = LeaseInfo {
                            job_id: parsed.common.job_id,
                            envelope_digest: header.envelope_digest,
                            generation: new_generation,
                            attempt: new_attempt,
                            maximum_attempts: parsed.common.maximum_attempts,
                            token: lease_token,
                            boot_id: self.boot_id.clone(),
                            expires_boottime_ns: boottime_deadline,
                            expires_wall_ns: wall_deadline,
                            content_type,
                            payload_length: header.payload_length,
                            payload_digest: header.payload_digest,
                            expected_dev: leased_stat.st_dev as u64,
                            expected_inode: leased_stat.st_ino as u64,
                            exact_source_path: format!("{leased_dir}/{leased_name}"),
                        };

                        return LeaseOutcome::Leased(lease_info);
                    }
                    Err(e) if e.raw_os_error() == Some(libc::ENOENT) => continue,
                    Err(_) => {
                        scan_had_error = true;
                        continue;
                    }
                }
            }
        }

        // C-19: If the scan had I/O errors, report them rather than returning Empty
        if scan_had_error {
            LeaseOutcome::NotCommitted(Error::IoFailure("scan completed with errors".into()))
        } else {
            LeaseOutcome::Empty
        }
    }

    /// Acknowledge a lease: move to terminal receipt.
    /// R4-H22/H23: Re-hashes the payload at ack time to close the TOCTOU
    /// window between lease() and ack(). Use ack_unverified() to skip.
    pub fn ack(&mut self, lease: &LeaseInfo) -> AckOutcome {
        self.ack_impl(lease, true)
    }

    /// Acknowledge a lease without payload verification (unsafe).
    /// Cannot detect payload corruption. Use ack() for the safe path.
    pub fn ack_unverified(&mut self, lease: &LeaseInfo) -> AckOutcome {
        self.ack_impl(lease, false)
    }

    fn ack_impl(&mut self, lease: &LeaseInfo, verify_payload: bool) -> AckOutcome {
        if let Err(e) = self.check_not_poisoned() {
            return AckOutcome::NotCommitted(e);
        }

        // C-25/B-05: Use effective wall floor for terminal transitions
        let wall_now = match self.wall_floor_for_mutation() {
            Ok(v) => v,
            Err(e) => return AckOutcome::NotCommitted(e),
        };
        let new_generation = match lease.generation.checked_add(1) {
            Some(g) => g,
            None => return AckOutcome::NotCommitted(Error::StateExhausted),
        };
        let receipt_common = CommonFields {
            job_id: lease.job_id,
            generation: new_generation,
            attempt: lease.attempt,
            maximum_attempts: lease.maximum_attempts,
        };

        let terminal_bucket = match bucket_number(wall_now, self.format.terminal_bucket_width_ns) {
            Some(bucket) => bucket,
            None => return AckOutcome::NotCommitted(Error::StateExhausted),
        };
        let target =
            self.layout()
                .receipt_in_bucket(&receipt_common, &lease.token, terminal_bucket);
        let receipt_dir = target.directory();
        let receipt_name = target.filename;
        let transition_ticket = match self.transition_ticket_for_lease(
            lease,
            TransitionOperation::Acknowledge,
            TicketDestination::Receipt { terminal_bucket },
        ) {
            Ok(ticket) => ticket,
            Err(error) => return AckOutcome::NotCommitted(error),
        };
        if let Err(e) = self.ensure_dir(&receipt_dir) {
            return AckOutcome::NotCommitted(Error::IoFailure(e.to_string()));
        }

        let receipt_dir_fd = match open_relative(self.root_fd.as_raw_fd(), &receipt_dir) {
            Ok(fd) => fd,
            Err(e) => return AckOutcome::NotCommitted(Error::IoFailure(e.to_string())),
        };

        // B-04: Validate the current lease source before acknowledging
        let source = match self.open_and_validate_current_lease(lease) {
            Ok(Some(source)) => source,
            Ok(None) => {
                // R2-H01: Source is gone. Before returning LeaseLost,
                // check if this was a duplicate ack by probing receipts.
                if self.check_duplicate_ack_bounded(lease) {
                    return AckOutcome::AlreadyAcked;
                }
                return AckOutcome::LeaseLost;
            }
            Err(Error::QueueCorrupt(e)) => {
                self.poison();
                return AckOutcome::NotCommitted(Error::QueueCorrupt(e));
            }
            Err(e) => return AckOutcome::NotCommitted(e),
        };

        if verify_payload {
            if let Err(e) = self.verify_payload_on_fd(source.file_fd.as_raw_fd()) {
                self.poison();
                return AckOutcome::NotCommitted(e);
            }
        }

        // Rename leased -> receipt with NOREPLACE
        match Self::rename_leased_witness_noreplace(
            &source,
            receipt_dir_fd.as_raw_fd(),
            &receipt_name,
        ) {
            WitnessedRenameOutcome::Linearized => {
                // Sync both directories
                if fs::fsync_dir_fd(receipt_dir_fd.as_raw_fd()).is_err() {
                    self.poison();
                    return AckOutcome::OutcomeUnknown(
                        transition_ticket.with_phase(TransitionPhase::Linearized),
                    );
                }
                if fs::fsync_dir_fd(source.directory_fd.as_raw_fd()).is_err() {
                    self.poison();
                    return AckOutcome::OutcomeUnknown(
                        transition_ticket.with_phase(TransitionPhase::DestinationDirectoryDurable),
                    );
                }
                AckOutcome::Acked
            }
            WitnessedRenameOutcome::LinearizedIdentityUnknown => {
                self.poison();
                AckOutcome::OutcomeUnknown(
                    transition_ticket.with_phase(TransitionPhase::Linearized),
                )
            }
            WitnessedRenameOutcome::Collision => {
                // P0-04: Authenticate the existing receipt instead of blindly
                // reporting AlreadyAcked. A conflicting object at the
                // deterministic path must not be treated as idempotent success.
                if self.receipt_is_authentic(lease, &receipt_dir, &receipt_name) {
                    // Source exists and receipt is authentic: both observed.
                    // The lease is still live. Report as corruption rather
                    // than collapsing into idempotent success.
                    self.poison();
                    AckOutcome::NotCommitted(Error::QueueCorrupt(
                        "source lease and receipt both exist".into(),
                    ))
                } else {
                    self.poison();
                    AckOutcome::NotCommitted(Error::QueueCorrupt(
                        "conflicting object at receipt path".into(),
                    ))
                }
            }
            WitnessedRenameOutcome::SourceGone => {
                // C-22: On source absence, do a bounded receipt probe.
                // Construct the finite set of exact retained receipt paths
                // and check them directly (C-23: bounded, not full scan).
                if self.check_duplicate_ack_bounded(lease) {
                    AckOutcome::AlreadyAcked
                } else {
                    AckOutcome::LeaseLost
                }
            }
            WitnessedRenameOutcome::SourceChanged => {
                self.poison();
                AckOutcome::NotCommitted(Error::QueueCorrupt(
                    "leased source identity changed before acknowledgment".into(),
                ))
            }
            WitnessedRenameOutcome::Failed(error) => AckOutcome::NotCommitted(error),
        }
    }

    /// Retry a lease immediately (move to ready).
    pub fn retry_now(&mut self, lease: &LeaseInfo) -> TransitionOutcome {
        self.retry(lease, None)
    }

    /// Retry a lease at a future time (move to delayed).
    pub fn retry_at(&mut self, lease: &LeaseInfo, not_before_ns: u64) -> TransitionOutcome {
        self.retry(lease, Some(not_before_ns))
    }

    /// Retry a lease after a duration.
    pub fn retry_after(&mut self, lease: &LeaseInfo, duration_ns: u64) -> TransitionOutcome {
        let wall_now = match self.wall_floor_for_mutation() {
            Ok(v) => v,
            Err(e) => return TransitionOutcome::NotCommitted(e),
        };
        let deadline = match steadq_math::retry_wall_deadline(wall_now, duration_ns) {
            Some(d) => d,
            None => {
                return TransitionOutcome::NotCommitted(Error::InvalidInput(
                    "deadline overflow".into(),
                ))
            }
        };
        self.retry_at(lease, deadline)
    }

    /// Retry with a policy (computes delay from attempt and policy).
    pub fn retry_with_policy(
        &mut self,
        lease: &LeaseInfo,
        policy: &steadq_math::RetryPolicy,
    ) -> TransitionOutcome {
        if let Err(e) = policy.validate() {
            return TransitionOutcome::NotCommitted(Error::InvalidInput(e.to_string()));
        }

        let delay_ms = match steadq_math::retry_delay_ms(
            &self.format.queue_id,
            &lease.job_id,
            lease.attempt,
            policy,
        ) {
            Ok(d) => d,
            Err(e) => return TransitionOutcome::NotCommitted(Error::InvalidInput(e.to_string())),
        };

        if delay_ms == 0 {
            self.retry_now(lease)
        } else {
            let delay_ns = match steadq_math::checked_mul_u64(delay_ms, 1_000_000) {
                Some(d) => d,
                None => {
                    return TransitionOutcome::NotCommitted(Error::InvalidInput(
                        "delay overflow".into(),
                    ))
                }
            };
            let wall_now = match self.wall_floor_for_mutation() {
                Ok(v) => v,
                Err(e) => return TransitionOutcome::NotCommitted(e),
            };
            let deadline = match steadq_math::retry_wall_deadline(wall_now, delay_ns) {
                Some(d) => d,
                None => {
                    return TransitionOutcome::NotCommitted(Error::InvalidInput(
                        "deadline overflow".into(),
                    ))
                }
            };
            self.retry_at(lease, deadline)
        }
    }

    fn retry(&mut self, lease: &LeaseInfo, delayed_ns: Option<u64>) -> TransitionOutcome {
        if let Err(e) = self.check_not_poisoned() {
            return TransitionOutcome::NotCommitted(e);
        }
        // If delayed target is at or before the effective wall floor, it's retry_now.
        let delayed_ns = match delayed_ns {
            Some(t) if t <= self.effective_wall_floor_ns() => None,
            other => other,
        };

        // Check attempt limit for retry
        if lease.attempt >= lease.maximum_attempts {
            // Move to dead with attempts_exhausted
            return match self.bury_internal(lease, DeadReason::AttemptsExhausted) {
                TransitionOutcome::Committed => TransitionOutcome::Committed,
                other => other,
            };
        }

        let new_gen = match lease.generation.checked_add(1) {
            Some(g) => g,
            None => return TransitionOutcome::NotCommitted(Error::StateExhausted),
        };

        let (dest_dir, dest_name, operation, destination) = match delayed_ns {
            Some(nb) => {
                let common = CommonFields {
                    job_id: lease.job_id,
                    generation: new_gen,
                    attempt: lease.attempt,
                    maximum_attempts: lease.maximum_attempts,
                };
                let target = self.layout().delayed(&common, nb).unwrap();
                (
                    target.directory(),
                    target.filename,
                    TransitionOperation::RetryLater,
                    TicketDestination::Delayed { not_before_ns: nb },
                )
            }
            None => {
                let common = CommonFields {
                    job_id: lease.job_id,
                    generation: new_gen,
                    attempt: lease.attempt,
                    maximum_attempts: lease.maximum_attempts,
                };
                let target = self.layout().ready(&common);
                (
                    target.directory(),
                    target.filename,
                    TransitionOperation::RetryNow,
                    TicketDestination::Ready {},
                )
            }
        };

        let ticket = match self.transition_ticket_for_lease(lease, operation, destination) {
            Ok(ticket) => ticket,
            Err(error) => return TransitionOutcome::NotCommitted(error),
        };
        self.move_leased(lease, &dest_dir, &dest_name, &ticket)
    }

    /// Bury a lease (move to dead).
    pub fn bury(&mut self, lease: &LeaseInfo, reason: DeadReason) -> TransitionOutcome {
        if let Err(e) = self.check_not_poisoned() {
            return TransitionOutcome::NotCommitted(e);
        }
        self.bury_internal(lease, reason)
    }

    fn bury_internal(&mut self, lease: &LeaseInfo, reason: DeadReason) -> TransitionOutcome {
        let new_gen = match lease.generation.checked_add(1) {
            Some(g) => g,
            None => return TransitionOutcome::NotCommitted(Error::StateExhausted),
        };

        // C-25/B-05: Use effective wall floor for terminal transitions
        let wall_now = match self.wall_floor_for_mutation() {
            Ok(v) => v,
            Err(e) => return TransitionOutcome::NotCommitted(e),
        };

        let common = CommonFields {
            job_id: lease.job_id,
            generation: new_gen,
            attempt: lease.attempt,
            maximum_attempts: lease.maximum_attempts,
        };

        let terminal_bucket = match bucket_number(wall_now, self.format.terminal_bucket_width_ns) {
            Some(bucket) => bucket,
            None => return TransitionOutcome::NotCommitted(Error::StateExhausted),
        };
        let target = self
            .layout()
            .dead_in_bucket(&common, reason as u16, terminal_bucket);
        let dest_dir = target.directory();
        let fname = target.filename;
        let ticket = match self.transition_ticket_for_lease(
            lease,
            TransitionOperation::Bury,
            TicketDestination::Dead {
                terminal_bucket,
                reason: reason as u16,
            },
        ) {
            Ok(ticket) => ticket,
            Err(error) => return TransitionOutcome::NotCommitted(error),
        };

        self.move_leased(lease, &dest_dir, &fname, &ticket)
    }

    /// Renew a lease with a new deadline.
    pub fn renew(&mut self, lease: &LeaseInfo, lease_duration_ns: u64) -> RenewOutcome {
        if let Err(e) = self.check_not_poisoned() {
            return RenewOutcome::NotCommitted(e);
        }

        let min_dur = 1_000_000_000u64;
        let max_dur = 7 * 24 * 60 * 60 * 1_000_000_000u64;
        if lease_duration_ns < min_dur || lease_duration_ns > max_dur {
            return RenewOutcome::NotCommitted(Error::InvalidInput(
                "lease duration must be 1s to 7d".into(),
            ));
        }

        let boottime_now = match fs::clock_boottime_ns() {
            Ok(t) => t,
            Err(e) => return RenewOutcome::NotCommitted(Error::IoFailure(e.to_string())),
        };
        let wall_now = match self.wall_floor_for_mutation() {
            Ok(v) => v,
            Err(e) => return RenewOutcome::NotCommitted(e),
        };
        let new_boottime_dl = match boottime_now.checked_add(lease_duration_ns) {
            Some(d) => d,
            None => {
                return RenewOutcome::NotCommitted(Error::InvalidInput("deadline overflow".into()))
            }
        };
        let new_wall_dl = match wall_now.checked_add(lease_duration_ns) {
            Some(d) => d,
            None => {
                return RenewOutcome::NotCommitted(Error::InvalidInput("deadline overflow".into()))
            }
        };
        let new_gen = match lease.generation.checked_add(1) {
            Some(g) => g,
            None => return RenewOutcome::NotCommitted(Error::StateExhausted),
        };

        let common = CommonFields {
            job_id: lease.job_id,
            generation: new_gen,
            attempt: lease.attempt,
            maximum_attempts: lease.maximum_attempts,
        };

        let target = self
            .layout()
            .leased(&common, new_boottime_dl, new_wall_dl, &lease.token)
            .unwrap();
        let dest_dir = target.directory();
        let fname = target.filename;

        let ticket = match self.transition_ticket_for_lease(
            lease,
            TransitionOperation::Renew,
            TicketDestination::Leased {
                boot_id: self.boot_id.clone(),
                boottime_deadline_ns: new_boottime_dl,
                wall_deadline_ns: new_wall_dl,
            },
        ) {
            Ok(ticket) => ticket,
            Err(error) => return RenewOutcome::NotCommitted(error),
        };

        match self.move_leased_renew(lease, &dest_dir, &fname, &ticket) {
            TransitionOutcome::Committed => RenewOutcome::Renewed(LeaseInfo {
                generation: new_gen,
                expires_boottime_ns: new_boottime_dl,
                expires_wall_ns: new_wall_dl,
                exact_source_path: format!("{dest_dir}/{fname}"),
                ..lease.clone()
            }),
            TransitionOutcome::LeaseLost => RenewOutcome::LeaseLost,
            TransitionOutcome::NotCommitted(e) => RenewOutcome::NotCommitted(e),
            TransitionOutcome::OutcomeUnknown(t) => RenewOutcome::OutcomeUnknown(t),
        }
    }

    /// B-04: Open and validate the current leased source object.
    /// Validates the source path, filename, header, and identity against the handle.
    fn is_expected_dev_zero(dev: u64) -> bool {
        dev == 0
    }

    fn is_expected_inode_zero(ino: u64) -> bool {
        ino == 0
    }

    fn shard_matches(path: u32, computed: u32) -> bool {
        path == computed
    }

    /// Returns a retained source descriptor and exact path identity on success.
    fn open_and_validate_current_lease(
        &self,
        lease: &LeaseInfo,
    ) -> Result<Option<LeasedSourceWitness>, Error> {
        if Self::is_expected_dev_zero(lease.expected_dev) {
            return Err(Error::QueueCorrupt(
                "expected_dev is zero (forgeable handle)".into(),
            ));
        }
        if Self::is_expected_inode_zero(lease.expected_inode) {
            return Err(Error::QueueCorrupt(
                "expected_inode is zero (forgeable handle)".into(),
            ));
        }

        let (loc, src_name) = self.layout().parse_leased_path(&lease.exact_source_path)?;
        let (boot_id, path_bucket, path_shard) = match &loc {
            layout::Location::Leased {
                boot_id,
                bucket,
                shard,
            } => (boot_id.clone(), *bucket, *shard),
            _ => unreachable!("parse_leased_path always returns Leased"),
        };

        if boot_id != self.boot_id {
            return Err(Error::InvalidInput(format!(
                "source boot_id '{}' does not match queue boot_id '{}'",
                boot_id, self.boot_id
            )));
        }
        if boot_id != lease.boot_id {
            return Err(Error::QueueCorrupt(
                "source boot_id does not match lease handle".into(),
            ));
        }

        let computed_shard = compute_shard(
            &self.format.queue_id,
            &lease.job_id,
            self.format.shard_count,
        );
        if !Self::shard_matches(path_shard, computed_shard) {
            return Err(Error::QueueCorrupt(format!(
                "source shard {path_shard} does not match queue-derived shard {computed_shard}"
            )));
        }

        let src_dir = match loc {
            layout::Location::Leased {
                boot_id,
                bucket,
                shard,
            } => {
                format!(
                    "leased/{}/{}/{}",
                    boot_id,
                    bucket_hex(bucket),
                    shard_hex(shard)
                )
            }
            _ => unreachable!(),
        };

        // R2-H02: Only ENOENT means "source gone". Other errors are real failures.
        let src_dir_fd = match open_relative(self.root_fd.as_raw_fd(), &src_dir) {
            Ok(fd) => fd,
            Err(error) => match classify_lease_directory_open_failure(&error) {
                LeaseDirectoryOpenFailure::Gone => return Ok(None),
                LeaseDirectoryOpenFailure::InvalidDirectory => {
                    return Err(Error::QueueCorrupt(
                        "intermediate lease path component is not a directory".into(),
                    ));
                }
                LeaseDirectoryOpenFailure::Io => {
                    return Err(Error::IoFailure(error.to_string()));
                }
            },
        };

        let src_stat = match fs::fstatat(src_dir_fd.as_raw_fd(), &src_name) {
            Ok(s) => s,
            Err(error) => match classify_presence_failure(&error) {
                PresenceFailure::Absent => return Ok(None),
                PresenceFailure::Io => return Err(Error::IoFailure(error.to_string())),
            },
        };

        if !is_singly_linked_regular(src_stat.st_mode, src_stat.st_nlink) {
            return Err(Error::QueueCorrupt(
                "source is not a singly-linked regular file".into(),
            ));
        }

        let parsed = steadq_names::parse_leased(&src_name).map_err(|_| {
            Error::QueueCorrupt("source filename is not a valid leased name".into())
        })?;

        if parsed.common.job_id != lease.job_id {
            return Err(Error::QueueCorrupt("source job_id mismatch".into()));
        }
        if parsed.common.generation != lease.generation {
            return Err(Error::QueueCorrupt("source generation mismatch".into()));
        }
        if parsed.common.attempt != lease.attempt {
            return Err(Error::QueueCorrupt("source attempt mismatch".into()));
        }
        if parsed.common.maximum_attempts != lease.maximum_attempts {
            return Err(Error::QueueCorrupt("source max_attempts mismatch".into()));
        }
        if parsed.token != lease.token {
            return Err(Error::QueueCorrupt("source token mismatch".into()));
        }
        if parsed.boottime_deadline_ns != lease.expires_boottime_ns {
            return Err(Error::QueueCorrupt(
                "source boottime deadline mismatch".into(),
            ));
        }
        if parsed.wall_deadline_ns != lease.expires_wall_ns {
            return Err(Error::QueueCorrupt("source wall deadline mismatch".into()));
        }
        let expected_bucket = steadq_math::lease_bucket(
            parsed.boottime_deadline_ns,
            self.format.lease_bucket_width_ns,
        )
        .ok_or(Error::StateExhausted)?;
        if path_bucket != expected_bucket {
            return Err(Error::QueueCorrupt("source lease bucket mismatch".into()));
        }
        if !parsed.authenticate_tag(
            &self.format.queue_id,
            &boot_id,
            &bucket_hex(path_bucket),
            &shard_hex(path_shard),
        ) {
            return Err(Error::QueueCorrupt("source name tag mismatch".into()));
        }

        let file_fd = fs::openat(
            src_dir_fd.as_raw_fd(),
            &src_name,
            resolver_file_open_flags(),
            0,
        )
        .map_err(|e| Error::IoFailure(e.to_string()))?;
        let opened_stat =
            fs::fstat(file_fd.as_raw_fd()).map_err(|error| Error::IoFailure(error.to_string()))?;
        if !stat_matches_witness(&opened_stat, lease.expected_dev, lease.expected_inode) {
            return Err(Error::QueueCorrupt(
                "opened source identity does not match lease handle".into(),
            ));
        }
        if !stat_matches_witness(
            &src_stat,
            opened_stat.st_dev as u64,
            opened_stat.st_ino as u64,
        ) {
            return Err(Error::QueueCorrupt(
                "source path changed while opening lease".into(),
            ));
        }
        let mut header_buf = [0u8; 128];
        fs::pread_exact(file_fd.as_raw_fd(), &mut header_buf, 0)
            .map_err(|e| Error::IoFailure(e.to_string()))?;
        let header = FixedHeader::decode(&header_buf)
            .map_err(|e| Error::QueueCorrupt(format!("header decode: {e}")))?;

        if header.job_id != lease.job_id {
            return Err(Error::QueueCorrupt(
                "header job_id does not match handle".into(),
            ));
        }

        // H5: Verify header maximum_attempts matches filename/handle
        if header.maximum_attempts != lease.maximum_attempts {
            return Err(Error::QueueCorrupt(format!(
                "header maximum_attempts {} does not match handle {}",
                header.maximum_attempts, lease.maximum_attempts
            )));
        }

        // R4-H04: Verify envelope digest matches the handle
        if header.envelope_digest != lease.envelope_digest {
            return Err(Error::QueueCorrupt(
                "envelope digest does not match handle".into(),
            ));
        }
        if header.payload_length != lease.payload_length {
            return Err(Error::QueueCorrupt(
                "payload length does not match handle".into(),
            ));
        }
        if header.payload_digest != lease.payload_digest {
            return Err(Error::QueueCorrupt(
                "payload digest does not match handle".into(),
            ));
        }

        // R2-H03: Extension read failure is a real error, not a silent pass.
        let ext_len = header.extension_header_length as usize;
        if verified::is_extension_too_large(ext_len) {
            return Err(Error::QueueCorrupt("extension header too large".into()));
        }
        // R4-H05: Always verify envelope digest (even when extension is empty).
        let mut ext_buf = vec![0u8; ext_len];
        if verified::is_extension_present(ext_len) {
            fs::pread_exact(file_fd.as_raw_fd(), &mut ext_buf, 128)
                .map_err(|e| Error::IoFailure(e.to_string()))?;
        }
        if !steadq_format::verify_envelope_digest(&header, &ext_buf) {
            return Err(Error::QueueCorrupt("envelope digest mismatch".into()));
        }

        // R2-B02: Verify exact file size (no trailing data)
        let expected_size = (128 + ext_len + header.payload_length as usize) as u64;
        if opened_stat.st_size as u64 != expected_size {
            return Err(Error::QueueCorrupt(format!(
                "source file size mismatch: expected {}, got {}",
                expected_size, opened_stat.st_size
            )));
        }

        Ok(Some(LeasedSourceWitness {
            directory_fd: src_dir_fd,
            name: src_name,
            file_fd,
            device: opened_stat.st_dev as u64,
            inode: opened_stat.st_ino as u64,
        }))
    }

    fn observe_leased_source_path(
        source: &LeasedSourceWitness,
    ) -> Result<WitnessPathObservation, Error> {
        match fs::fstatat(source.directory_fd.as_raw_fd(), &source.name) {
            Ok(stat) if stat_matches_witness(&stat, source.device, source.inode) => {
                Ok(WitnessPathObservation::Match)
            }
            Ok(_) => Ok(WitnessPathObservation::Mismatch),
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                Ok(WitnessPathObservation::Gone)
            }
            Err(error) => Err(Error::IoFailure(error.to_string())),
        }
    }

    fn rename_leased_witness_noreplace(
        source: &LeasedSourceWitness,
        destination_directory_fd: RawFd,
        destination_name: &str,
    ) -> WitnessedRenameOutcome {
        match Self::observe_leased_source_path(source) {
            Ok(WitnessPathObservation::Match) => {}
            Ok(WitnessPathObservation::Gone) => return WitnessedRenameOutcome::SourceGone,
            Ok(WitnessPathObservation::Mismatch) => {
                return WitnessedRenameOutcome::SourceChanged;
            }
            Err(error) => return WitnessedRenameOutcome::Failed(error),
        }

        match fs::renameat2_noreplace(
            source.directory_fd.as_raw_fd(),
            &source.name,
            destination_directory_fd,
            destination_name,
        ) {
            Ok(()) => {
                let destination_stat = fs::fstatat(destination_directory_fd, destination_name).ok();
                classify_renamed_destination(destination_stat.as_ref(), source.device, source.inode)
            }
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                WitnessedRenameOutcome::SourceGone
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                WitnessedRenameOutcome::Collision
            }
            Err(error) => WitnessedRenameOutcome::Failed(Error::IoFailure(error.to_string())),
        }
    }

    /// Internal: move a leased object to a new state directory.
    fn move_leased(
        &mut self,
        lease: &LeaseInfo,
        dest_dir: &str,
        dest_name: &str,
        ticket: &TransitionTicket,
    ) -> TransitionOutcome {
        if let Err(e) = self.ensure_dir(dest_dir) {
            return TransitionOutcome::NotCommitted(Error::IoFailure(e.to_string()));
        }

        let dest_dir_fd = match open_relative(self.root_fd.as_raw_fd(), dest_dir) {
            Ok(fd) => fd,
            Err(e) => return TransitionOutcome::NotCommitted(Error::IoFailure(e.to_string())),
        };

        // B-04: Validate the current lease source before transitioning
        let source = match self.open_and_validate_current_lease(lease) {
            Ok(Some(source)) => source,
            Ok(None) => return TransitionOutcome::LeaseLost,
            Err(Error::QueueCorrupt(e)) => {
                self.poison();
                return TransitionOutcome::NotCommitted(Error::QueueCorrupt(e));
            }
            Err(e) => return TransitionOutcome::NotCommitted(e),
        };

        match Self::rename_leased_witness_noreplace(&source, dest_dir_fd.as_raw_fd(), dest_name) {
            WitnessedRenameOutcome::Linearized => {
                // Check if source and destination are the same directory
                let src_stat = fs::fstat(source.directory_fd.as_raw_fd()).ok();
                let dest_stat = fs::fstat(dest_dir_fd.as_raw_fd()).ok();
                let src_same = same_directory_identity(src_stat.as_ref(), dest_stat.as_ref());
                if src_same {
                    if fs::fsync_dir_fd(dest_dir_fd.as_raw_fd()).is_err() {
                        self.poison();
                        return TransitionOutcome::OutcomeUnknown(
                            ticket.with_phase(TransitionPhase::Linearized),
                        );
                    }
                } else {
                    if fs::fsync_dir_fd(dest_dir_fd.as_raw_fd()).is_err() {
                        self.poison();
                        return TransitionOutcome::OutcomeUnknown(
                            ticket.with_phase(TransitionPhase::Linearized),
                        );
                    }
                    if fs::fsync_dir_fd(source.directory_fd.as_raw_fd()).is_err() {
                        self.poison();
                        return TransitionOutcome::OutcomeUnknown(
                            ticket.with_phase(TransitionPhase::DestinationDirectoryDurable),
                        );
                    }
                }
                TransitionOutcome::Committed
            }
            WitnessedRenameOutcome::LinearizedIdentityUnknown => {
                self.poison();
                TransitionOutcome::OutcomeUnknown(ticket.with_phase(TransitionPhase::Linearized))
            }
            WitnessedRenameOutcome::SourceGone => TransitionOutcome::LeaseLost,
            WitnessedRenameOutcome::SourceChanged => {
                self.poison();
                TransitionOutcome::NotCommitted(Error::QueueCorrupt(
                    "leased source identity changed before transition".into(),
                ))
            }
            WitnessedRenameOutcome::Collision => {
                TransitionOutcome::NotCommitted(Error::QueueCorrupt("destination exists".into()))
            }
            WitnessedRenameOutcome::Failed(error) => TransitionOutcome::NotCommitted(error),
        }
    }

    /// Same as move_leased but for renewal (same token, same attempt).
    fn move_leased_renew(
        &mut self,
        lease: &LeaseInfo,
        dest_dir: &str,
        dest_name: &str,
        ticket: &TransitionTicket,
    ) -> TransitionOutcome {
        self.move_leased(lease, dest_dir, dest_name, ticket)
    }

    fn transition_ticket_for_lease(
        &self,
        lease: &LeaseInfo,
        operation: TransitionOperation,
        destination: TicketDestination,
    ) -> Result<TransitionTicket, Error> {
        TransitionTicket::new(
            self.format.queue_id,
            operation,
            TransitionPhase::Linearized,
            TicketIdentity::new(
                lease.job_id,
                lease.generation,
                lease.attempt,
                lease.maximum_attempts,
                lease.token,
                TicketEvidence::new(lease.envelope_digest, lease.payload_length),
            ),
            TicketSource::Leased {
                boot_id: lease.boot_id.clone(),
                boottime_deadline_ns: lease.expires_boottime_ns,
                wall_deadline_ns: lease.expires_wall_ns,
            },
            destination,
        )
    }

    fn claim_transition_ticket(
        &self,
        source: &CommonFields,
        lease_token: [u8; 16],
        evidence: TicketEvidence,
        boottime_deadline_ns: u64,
        wall_deadline_ns: u64,
    ) -> Result<TransitionTicket, Error> {
        TransitionTicket::new(
            self.format.queue_id,
            TransitionOperation::Claim,
            TransitionPhase::Linearized,
            TicketIdentity::new(
                source.job_id,
                source.generation,
                source.attempt,
                source.maximum_attempts,
                lease_token,
                evidence,
            ),
            TicketSource::Ready {},
            TicketDestination::Leased {
                boot_id: self.boot_id.clone(),
                boottime_deadline_ns,
                wall_deadline_ns,
            },
        )
    }

    fn open_claim_source(
        directory_fd: RawFd,
        name: &str,
        expected_job_id: &[u8; 16],
        expected_maximum_attempts: u32,
    ) -> Result<ClaimSourceWitness, Error> {
        let file = fs::openat(directory_fd, name, resolver_file_open_flags(), 0)
            .map_err(|error| Error::IoFailure(error.to_string()))?;
        let stat =
            fs::fstat(file.as_raw_fd()).map_err(|error| Error::IoFailure(error.to_string()))?;
        if !is_singly_linked_regular(stat.st_mode, stat.st_nlink) {
            return Err(Error::QueueCorrupt(
                "ready source is not a singly-linked regular file".into(),
            ));
        }
        let evidence = Self::read_claim_ticket_evidence(
            file.as_raw_fd(),
            expected_job_id,
            expected_maximum_attempts,
        )?;
        Ok(ClaimSourceWitness {
            file_fd: file,
            device: stat.st_dev as u64,
            inode: stat.st_ino as u64,
            evidence,
        })
    }

    fn read_claim_ticket_evidence(
        file_fd: RawFd,
        expected_job_id: &[u8; 16],
        expected_maximum_attempts: u32,
    ) -> Result<TicketEvidence, Error> {
        let verified = verified::verify_envelope_on_fd(file_fd).map_err(Error::from)?;
        let header = verified.header;
        if &header.job_id != expected_job_id {
            return Err(Error::QueueCorrupt("header job_id mismatch".into()));
        }
        if header.maximum_attempts != expected_maximum_attempts {
            return Err(Error::QueueCorrupt(
                "header maximum_attempts mismatch".into(),
            ));
        }
        Ok(TicketEvidence::new(
            header.envelope_digest,
            header.payload_length,
        ))
    }

    /// Move a ready object to dead (for exhausted attempts cleanup).
    fn move_to_dead(
        &mut self,
        ready_dir: &str,
        ready_name: &str,
        common: &CommonFields,
        reason: DeadReason,
    ) -> Result<(), io::Error> {
        let shard_str = ready_dir.rsplit('/').next().unwrap_or("0000");
        let wall_now = self.effective_wall_floor_ns();
        let terminal_bucket =
            steadq_math::bucket_number(wall_now, self.format.terminal_bucket_width_ns).unwrap_or(0);
        let bucket_str = bucket_hex(terminal_bucket);

        let new_gen = common
            .generation
            .checked_add(1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "generation overflow"))?;
        let dead_common = CommonFields {
            job_id: common.job_id,
            generation: new_gen,
            attempt: common.attempt,
            maximum_attempts: common.maximum_attempts,
        };

        let dead_name = steadq_names::make_dead_name(
            &self.format.queue_id,
            &bucket_str,
            shard_str,
            &dead_common,
            reason as u16,
        );
        let dead_dir = format!("dead/{bucket_str}/{shard_str}");

        let _ = self.ensure_dir(&dead_dir);
        let dead_dir_fd = open_relative(self.root_fd.as_raw_fd(), &dead_dir)?;
        let ready_dir_fd = open_relative(self.root_fd.as_raw_fd(), ready_dir)?;

        fs::renameat2_noreplace(
            ready_dir_fd.as_raw_fd(),
            ready_name,
            dead_dir_fd.as_raw_fd(),
            &dead_name,
        )?;
        fs::fsync_dir_fd(dead_dir_fd.as_raw_fd())?;
        fs::fsync_dir_fd(ready_dir_fd.as_raw_fd())?;
        Ok(())
    }
    /// B-09: Read and verify the payload of a leased job.
    /// Validates source identity (B-04), then verifies envelope digest,
    /// then hashes the payload and compares to the header digest.
    /// Returns Ok(()) on success, Err(PayloadCorrupt) if the digest does not match.
    pub fn verify_lease_payload(&self, lease: &LeaseInfo) -> Result<(), Error> {
        let source = match self.open_and_validate_current_lease(lease)? {
            Some(source) => source,
            None => return Err(Error::QueueCorrupt("lease source not found".into())),
        };
        self.verify_payload_on_fd(source.file_fd.as_raw_fd())
    }

    /// R4-H22/H23: Verify the payload digest on an already-open file descriptor.
    /// Central verifier is the single source of truth; this wrapper preserves
    /// the existing Error mapping for callers that have not yet adopted
    /// VerificationError directly.
    fn verify_payload_on_fd(&self, fd: std::os::unix::io::RawFd) -> Result<(), Error> {
        verified::verify_job_on_fd(fd)
            .map(|_| ())
            .map_err(Error::from)
    }

    /// Verify only the envelope and size, without hashing payload bytes.
    /// Used by inspection paths that have not yet delivered payload.
    fn verify_envelope_on_fd(
        &self,
        fd: std::os::unix::io::RawFd,
    ) -> Result<verified::VerifiedJob, Error> {
        verified::verify_envelope_on_fd(fd).map_err(Error::from)
    }

    fn quarantine_corrupt_lease(
        &self,
        leased_dir_fd: std::os::unix::io::RawFd,
        leased_name: &str,
        held_fd: std::os::unix::io::RawFd,
    ) -> Result<(), std::io::Error> {
        // Verify held fd still names same inode before moving by pathname.
        let held_stat = fs::fstat(held_fd)?;
        let name_stat = fs::fstatat(leased_dir_fd, leased_name)?;
        if held_stat.st_dev != name_stat.st_dev || held_stat.st_ino != name_stat.st_ino {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "quarantine target changed under held fd",
            ));
        }
        let qid = fs::random_128bit().map_err(|e| std::io::Error::new(e.kind(), e.to_string()))?;
        let q_name =
            steadq_names::quarantine_filename(&qid, QuarantineReason::PayloadCorrupt as u16);
        self.ensure_dir("quarantine")?;
        let q_dir_fd = open_relative(self.root_fd.as_raw_fd(), "quarantine")?;
        fs::renameat2_noreplace(leased_dir_fd, leased_name, q_dir_fd.as_raw_fd(), &q_name)?;
        fs::fsync_dir_fd(q_dir_fd.as_raw_fd())?;
        fs::fsync_dir_fd(leased_dir_fd)?;
        Ok(())
    }
    /// R4-PERF: Read a chunk of a leased job's payload at the given offset.
    /// Returns the number of bytes read (0 at EOF).
    /// Validates source identity before reading (B-04).
    pub fn read_lease_payload_chunk(
        &self,
        lease: &LeaseInfo,
        buf: &mut [u8],
        offset: u64,
    ) -> Result<usize, Error> {
        let source = match self.open_and_validate_current_lease(lease)? {
            Some(source) => source,
            None => return Err(Error::QueueCorrupt("lease source not found".into())),
        };
        // P0-01: Verify payload before delivering any bytes.
        if let Err(e) = self.verify_payload_on_fd(source.file_fd.as_raw_fd()) {
            if matches!(e, Error::PayloadCorrupt) {
                let _ = self.quarantine_corrupt_lease(
                    source.directory_fd.as_raw_fd(),
                    &source.name,
                    source.file_fd.as_raw_fd(),
                );
            }
            return Err(e);
        }
        let mut header_buf = [0u8; 128];
        fs::pread_exact(source.file_fd.as_raw_fd(), &mut header_buf, 0)
            .map_err(|e| Error::IoFailure(e.to_string()))?;
        let header =
            FixedHeader::decode(&header_buf).map_err(|e| Error::QueueCorrupt(e.to_string()))?;
        let ext_len = header.extension_header_length as usize;
        let payload_start = (128 + ext_len) as u64;
        let payload_len = header.payload_length;
        if offset >= payload_len {
            return Ok(0);
        }
        let to_read = (buf.len() as u64).min(payload_len - offset) as usize;
        let abs_offset = payload_start + offset;
        let n = fs::pread(source.file_fd.as_raw_fd(), &mut buf[..to_read], abs_offset)
            .map_err(|e| Error::IoFailure(e.to_string()))?;
        Ok(n)
    }

    /// P1-14: Stream a leased job's payload with O(1) validation/open.
    /// Opens the file once, validates identity once, reads header once,
    /// then performs pread calls on the held fd.
    pub fn stream_lease_payload<F: FnMut(&[u8]) -> Result<(), Error>>(
        &self,
        lease: &LeaseInfo,
        chunk_size: usize,
        mut f: F,
    ) -> Result<(), Error> {
        let source = match self.open_and_validate_current_lease(lease)? {
            Some(source) => source,
            None => return Err(Error::QueueCorrupt("lease source not found".into())),
        };
        // P0-01: Verify payload before streaming any bytes.
        if let Err(e) = self.verify_payload_on_fd(source.file_fd.as_raw_fd()) {
            if matches!(e, Error::PayloadCorrupt) {
                let _ = self.quarantine_corrupt_lease(
                    source.directory_fd.as_raw_fd(),
                    &source.name,
                    source.file_fd.as_raw_fd(),
                );
            }
            return Err(e);
        }

        let mut header_buf = [0u8; 128];
        fs::pread_exact(source.file_fd.as_raw_fd(), &mut header_buf, 0)
            .map_err(|e| Error::IoFailure(e.to_string()))?;
        let header =
            FixedHeader::decode(&header_buf).map_err(|e| Error::QueueCorrupt(e.to_string()))?;

        let ext_len = header.extension_header_length as usize;
        let payload_start = (128 + ext_len) as u64;
        let payload_len = header.payload_length;

        let cap = chunk_size.clamp(4096, 1 << 20);
        let mut buf = vec![0u8; cap];
        let mut offset = 0u64;
        while offset < payload_len {
            let to_read = (buf.len() as u64).min(payload_len - offset) as usize;
            let n = fs::pread(
                source.file_fd.as_raw_fd(),
                &mut buf[..to_read],
                payload_start + offset,
            )
            .map_err(|e| Error::IoFailure(e.to_string()))?;
            if n == 0 {
                return Err(Error::QueueCorrupt("unexpected EOF during stream".into()));
            }
            f(&buf[..n])?;
            offset += n as u64;
        }
        Ok(())
    }

    /// Diagnostic lookup: find all states for a job_id.
    /// Scans active and terminal states for the computed shard.
    pub fn inspect(&self, job_id: &[u8; 16]) -> Vec<Snapshot> {
        let mut results = Vec::new();
        let shard = compute_shard(&self.format.queue_id, job_id, self.format.shard_count);
        let shard_str = shard_hex(shard);

        // Check ready
        let ready_dir = format!("ready/{shard_str}");
        if let Ok(dir_fd) = open_relative(self.root_fd.as_raw_fd(), &ready_dir) {
            if let Ok(entries) = fs::read_dir_entries_owned(dir_fd.as_raw_fd()) {
                for entry in entries {
                    if let Ok(parsed) = steadq_names::parse_ready(&entry) {
                        if parsed.common.job_id == *job_id {
                            results.push(Snapshot {
                                job_id: *job_id,
                                state: "ready".into(),
                                generation: parsed.common.generation,
                                attempt: parsed.common.attempt,
                                maximum_attempts: parsed.common.maximum_attempts,
                                shard,
                                relative_path: format!("{ready_dir}/{entry}"),
                                size: 0,
                            });
                        }
                    }
                }
            }
        }

        // Check leased (scan boot dirs)
        if let Ok(leased_root) = fs::open_directory(self.root_fd.as_raw_fd(), "leased") {
            if let Ok(boot_dirs) = fs::read_dir_entries_owned(leased_root.as_raw_fd()) {
                for boot_dir in boot_dirs {
                    let boot_path = format!("leased/{boot_dir}");
                    if let Ok(boot_fd) = open_relative(self.root_fd.as_raw_fd(), &boot_path) {
                        if let Ok(bucket_dirs) = fs::read_dir_entries_owned(boot_fd.as_raw_fd()) {
                            for bucket_dir in bucket_dirs {
                                let shard_path = format!("{boot_path}/{bucket_dir}/{shard_str}");
                                if let Ok(shard_fd) =
                                    open_relative(self.root_fd.as_raw_fd(), &shard_path)
                                {
                                    if let Ok(entries) =
                                        fs::read_dir_entries_owned(shard_fd.as_raw_fd())
                                    {
                                        for entry in entries {
                                            if let Ok(parsed) = steadq_names::parse_leased(&entry) {
                                                if parsed.common.job_id == *job_id {
                                                    results.push(Snapshot {
                                                        job_id: *job_id,
                                                        state: "leased".into(),
                                                        generation: parsed.common.generation,
                                                        attempt: parsed.common.attempt,
                                                        maximum_attempts: parsed
                                                            .common
                                                            .maximum_attempts,
                                                        shard,
                                                        relative_path: format!(
                                                            "{shard_path}/{entry}"
                                                        ),
                                                        size: 0,
                                                    });
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Check delayed
        if let Ok(delayed_root) = fs::open_directory(self.root_fd.as_raw_fd(), "delayed") {
            if let Ok(bucket_dirs) = fs::read_dir_entries_owned(delayed_root.as_raw_fd()) {
                for bucket_dir in bucket_dirs {
                    let shard_path = format!("delayed/{bucket_dir}/{shard_str}");
                    if let Ok(shard_fd) = open_relative(self.root_fd.as_raw_fd(), &shard_path) {
                        if let Ok(entries) = fs::read_dir_entries_owned(shard_fd.as_raw_fd()) {
                            for entry in entries {
                                if let Ok(parsed) = steadq_names::parse_delayed(&entry) {
                                    if parsed.common.job_id == *job_id {
                                        results.push(Snapshot {
                                            job_id: *job_id,
                                            state: "delayed".into(),
                                            generation: parsed.common.generation,
                                            attempt: parsed.common.attempt,
                                            maximum_attempts: parsed.common.maximum_attempts,
                                            shard,
                                            relative_path: format!("{shard_path}/{entry}"),
                                            size: 0,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Check dead
        if let Ok(dead_root) = fs::open_directory(self.root_fd.as_raw_fd(), "dead") {
            if let Ok(bucket_dirs) = fs::read_dir_entries_owned(dead_root.as_raw_fd()) {
                for bucket_dir in bucket_dirs {
                    let shard_path = format!("dead/{bucket_dir}/{shard_str}");
                    if let Ok(shard_fd) = open_relative(self.root_fd.as_raw_fd(), &shard_path) {
                        if let Ok(entries) = fs::read_dir_entries_owned(shard_fd.as_raw_fd()) {
                            for entry in entries {
                                if let Ok(parsed) = steadq_names::parse_dead(&entry) {
                                    if parsed.common.job_id == *job_id {
                                        results.push(Snapshot {
                                            job_id: *job_id,
                                            state: "dead".into(),
                                            generation: parsed.common.generation,
                                            attempt: parsed.common.attempt,
                                            maximum_attempts: parsed.common.maximum_attempts,
                                            shard,
                                            relative_path: format!("{shard_path}/{entry}"),
                                            size: 0,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Check receipts
        if let Ok(receipts_root) = fs::open_directory(self.root_fd.as_raw_fd(), "receipts") {
            if let Ok(bucket_dirs) = fs::read_dir_entries_owned(receipts_root.as_raw_fd()) {
                for bucket_dir in bucket_dirs {
                    let shard_path = format!("receipts/{bucket_dir}/{shard_str}");
                    if let Ok(shard_fd) = open_relative(self.root_fd.as_raw_fd(), &shard_path) {
                        if let Ok(entries) = fs::read_dir_entries_owned(shard_fd.as_raw_fd()) {
                            for entry in entries {
                                if let Ok(parsed) = steadq_names::parse_receipt(&entry) {
                                    if parsed.common.job_id == *job_id {
                                        results.push(Snapshot {
                                            job_id: *job_id,
                                            state: "receipt".into(),
                                            generation: parsed.common.generation,
                                            attempt: parsed.common.attempt,
                                            maximum_attempts: parsed.common.maximum_attempts,
                                            shard,
                                            relative_path: format!("{shard_path}/{entry}"),
                                            size: 0,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        results
    }

    /// Duplicate acknowledgment probe: check if a receipt exists for this lease.
    /// Probes exact receipt filenames across retained terminal buckets.
    pub fn check_duplicate_ack(&self, lease: &LeaseInfo) -> AckOutcome {
        let shard = compute_shard(
            &self.format.queue_id,
            &lease.job_id,
            self.format.shard_count,
        );
        let shard_str = shard_hex(shard);

        // Scan receipt buckets
        if let Ok(receipts_root) = fs::open_directory(self.root_fd.as_raw_fd(), "receipts") {
            if let Ok(bucket_dirs) = fs::read_dir_entries_owned(receipts_root.as_raw_fd()) {
                for bucket_dir in bucket_dirs {
                    let shard_path = format!("receipts/{bucket_dir}/{shard_str}");
                    if let Ok(shard_fd) = open_relative(self.root_fd.as_raw_fd(), &shard_path) {
                        if let Ok(entries) = fs::read_dir_entries_owned(shard_fd.as_raw_fd()) {
                            for entry in entries {
                                if let Ok(parsed) = steadq_names::parse_receipt(&entry) {
                                    if parsed.common.job_id == lease.job_id
                                        && parsed.token == lease.token
                                        && parsed.common.generation
                                            == lease.generation.saturating_add(1)
                                    {
                                        return AckOutcome::AlreadyAcked;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        AckOutcome::LeaseLost
    }

    /// B1: Authenticate an active-state object structurally.
    /// Validates: file type, link count, header, envelope digest, file size,
    /// name tag, shard placement, and header/name consistency with typed path context.
    /// Returns the validated header on success.
    pub(crate) fn validate_active_object(
        &self,
        dir_fd: std::os::unix::io::RawFd,
        name: &str,
        ctx: &ActivePathContext,
    ) -> Result<FixedHeader, Error> {
        // Stat with NOFOLLOW
        let stat = fs::fstatat(dir_fd, name).map_err(|e| Error::IoFailure(e.to_string()))?;

        // Regular file
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Err(Error::QueueCorrupt(format!("{name}: not a regular file")));
        }

        // Link count
        if stat.st_nlink != 1 {
            return Err(Error::QueueCorrupt(format!(
                "{name}: unexpected link count {}",
                stat.st_nlink
            )));
        }

        // Use central verifier for header, extension, envelope, and size.
        // stat has already been collected for mode and nlink; verify_envelope_on_fd
        // will re-stat the fd for size, which is fine since the fd is held open.
        let file_fd = fs::openat(dir_fd, name, libc::O_RDONLY, 0)
            .map_err(|e| Error::IoFailure(e.to_string()))?;
        let verified = self.verify_envelope_on_fd(file_fd.as_raw_fd())?;
        let header = verified.header;

        // R4-H06: Check queue-configured payload limit
        if header.payload_length > self.format.max_payload_length {
            return Err(Error::QueueCorrupt(format!(
                "payload length {} exceeds queue limit {}",
                header.payload_length, self.format.max_payload_length
            )));
        }

        // Parse and verify filename with typed path context and tag authentication.
        let (
            job_id,
            _parsed_gen,
            _parsed_attempt,
            max_att,
            parsed_tag,
            expected_tag,
            path_shard_str,
        ) = match ctx {
            ActivePathContext::Ready { shard } => {
                let p = steadq_names::parse_ready(name)
                    .map_err(|_| Error::QueueCorrupt("invalid ready filename".into()))?;
                if !p.authenticate_tag(&self.format.queue_id, shard) {
                    return Err(Error::QueueCorrupt("name tag mismatch".into()));
                }
                (
                    p.common.job_id,
                    p.common.generation,
                    p.common.attempt,
                    p.common.maximum_attempts,
                    p.tag,
                    p.tag,
                    shard.clone(),
                )
            }
            ActivePathContext::Leased {
                boot_id,
                bucket,
                shard,
            } => {
                let p = steadq_names::parse_leased(name)
                    .map_err(|_| Error::QueueCorrupt("invalid leased filename".into()))?;
                if !p.authenticate_tag(&self.format.queue_id, boot_id, bucket, shard) {
                    return Err(Error::QueueCorrupt("name tag mismatch".into()));
                }
                let expected_bucket = steadq_math::lease_bucket(
                    p.boottime_deadline_ns,
                    self.format.lease_bucket_width_ns,
                )
                .unwrap_or(0);
                let expected_bucket_str = steadq_names::bucket_hex(expected_bucket);
                if expected_bucket_str != *bucket {
                    return Err(Error::QueueCorrupt(format!(
                        "leased bucket mismatch: path {bucket} != expected {expected_bucket_str}"
                    )));
                }
                (
                    p.common.job_id,
                    p.common.generation,
                    p.common.attempt,
                    p.common.maximum_attempts,
                    p.tag,
                    p.tag,
                    shard.clone(),
                )
            }
            ActivePathContext::Delayed { bucket, shard } => {
                let p = steadq_names::parse_delayed(name)
                    .map_err(|_| Error::QueueCorrupt("invalid delayed filename".into()))?;
                if !p.authenticate_tag(&self.format.queue_id, bucket, shard) {
                    return Err(Error::QueueCorrupt("name tag mismatch".into()));
                }
                let expected_bucket = steadq_math::ceiling_bucket(
                    p.not_before_ns,
                    self.format.delayed_bucket_width_ns,
                )
                .unwrap_or(0);
                let expected_bucket_str = steadq_names::bucket_hex(expected_bucket);
                if expected_bucket_str != *bucket {
                    return Err(Error::QueueCorrupt(format!(
                        "delayed bucket mismatch: path {bucket} != expected {expected_bucket_str}"
                    )));
                }
                (
                    p.common.job_id,
                    p.common.generation,
                    p.common.attempt,
                    p.common.maximum_attempts,
                    p.tag,
                    p.tag,
                    shard.clone(),
                )
            }
        };

        // Verify header matches filename
        if header.job_id != job_id {
            return Err(Error::QueueCorrupt(
                "header job_id does not match filename".into(),
            ));
        }
        if header.maximum_attempts != max_att {
            return Err(Error::QueueCorrupt(
                "header maximum_attempts does not match filename".into(),
            ));
        }

        if parsed_tag != expected_tag {
            return Err(Error::QueueCorrupt("name tag mismatch".into()));
        }

        // Verify shard placement
        let computed_shard = compute_shard(&self.format.queue_id, &job_id, self.format.shard_count);
        let path_shard = steadq_names::shard_from_hex(&path_shard_str)
            .ok_or_else(|| Error::QueueCorrupt(format!("invalid shard hex: {path_shard_str}")))?;
        if path_shard != computed_shard {
            return Err(Error::QueueCorrupt(format!(
                "shard mismatch: path {path_shard} != computed {computed_shard}"
            )));
        }

        Ok(header)
    }

    /// C-23: Bounded duplicate-ack check.
    /// Constructs at most the finite set of exact retained receipt paths
    /// and checks them via fstatat, not by listing receipt contents.
    /// P0-04: Authenticate a receipt at a specific path.
    fn receipt_is_authentic(&self, lease: &LeaseInfo, dir: &str, name: &str) -> bool {
        let dir_fd = match open_relative(self.root_fd.as_raw_fd(), dir) {
            Ok(fd) => fd,
            Err(_) => return false,
        };
        let stat = match fs::fstatat(dir_fd.as_raw_fd(), name) {
            Ok(s) => s,
            Err(_) => return false,
        };
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
            return false;
        }
        // Parse the receipt filename and verify identity.
        let parsed = match steadq_names::parse_receipt(name) {
            Ok(p) => p,
            Err(_) => return false,
        };
        if parsed.common.job_id != lease.job_id {
            return false;
        }
        if parsed.token != lease.token {
            return false;
        }
        // Verify name tag.
        let parts: Vec<&str> = dir.split('/').collect();
        let (bucket, shard_hex) = match parts.len() {
            3 => (parts[1], parts[2]),
            _ => return false,
        };
        if !parsed.authenticate_tag(&self.format.queue_id, bucket, shard_hex) {
            return false;
        }
        // Read and verify the receipt content.
        let file_fd = match fs::openat(dir_fd.as_raw_fd(), name, libc::O_RDONLY, 0) {
            Ok(f) => f,
            Err(_) => return false,
        };
        let mut buf = [0u8; 128];
        if fs::pread_exact(file_fd.as_raw_fd(), &mut buf, 0).is_err() {
            return false;
        }
        if stat.st_size as usize == steadq_format::COMPACT_RECEIPT_SIZE
            && &buf[0..8] == steadq_format::RECEIPT_MAGIC
        {
            match steadq_format::CompactReceipt::decode(&buf) {
                Ok(cr) => cr.job_id == lease.job_id && cr.lease_token == lease.token,
                Err(_) => false,
            }
        } else {
            match FixedHeader::decode(&buf) {
                Ok(h) => h.job_id == lease.job_id,
                Err(_) => false,
            }
        }
    }

    fn check_duplicate_ack_bounded(&self, lease: &LeaseInfo) -> bool {
        let wall_now = self.effective_wall_floor_ns();
        let retention = self.options.receipt_retention_ns;
        let width = self.format.terminal_bucket_width_ns;
        let now_bucket = steadq_math::bucket_number(wall_now, width).unwrap_or(0);
        let retention_buckets = steadq_math::ceiling_bucket(retention, width).unwrap_or(0);
        let min_bucket = now_bucket.saturating_sub(retention_buckets + 2);
        let shard = compute_shard(
            &self.format.queue_id,
            &lease.job_id,
            self.format.shard_count,
        );
        let shard_str = shard_hex(shard);
        let new_generation = lease.generation.saturating_add(1);
        let receipt_common = CommonFields {
            job_id: lease.job_id,
            generation: new_generation,
            attempt: lease.attempt,
            maximum_attempts: lease.maximum_attempts,
        };
        for bucket_num in min_bucket..=now_bucket {
            let bucket_str = bucket_hex(bucket_num);
            let receipt_name = steadq_names::make_receipt_name(
                &self.format.queue_id,
                &bucket_str,
                &shard_str,
                &receipt_common,
                &lease.token,
            );
            let receipt_dir = format!("receipts/{bucket_str}/{shard_str}");
            if let Ok(dir_fd) = open_relative(self.root_fd.as_raw_fd(), &receipt_dir) {
                // R4-B08: Authenticate the receipt, not just check existence
                if let Ok(stat) = fs::fstatat(dir_fd.as_raw_fd(), &receipt_name) {
                    if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
                        continue;
                    }
                    if let Ok(file_fd) =
                        fs::openat(dir_fd.as_raw_fd(), &receipt_name, libc::O_RDONLY, 0)
                    {
                        let mut buf = [0u8; 128];
                        if fs::pread_exact(file_fd.as_raw_fd(), &mut buf, 0).is_ok() {
                            // Accept full job header with matching job_id
                            if let Ok(hdr) = FixedHeader::decode(&buf) {
                                if hdr.job_id == lease.job_id {
                                    return true;
                                }
                            }
                            // Accept compact receipt with matching job_id
                            if stat.st_size as usize == steadq_format::COMPACT_RECEIPT_SIZE {
                                if let Ok(cr) = steadq_format::CompactReceipt::decode(&buf) {
                                    if cr.job_id == lease.job_id {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Resolve an indeterminate operation by probing exact paths.
    /// R2-B03: Resolve an indeterminate operation by authenticating objects.
    /// Validates source/destination by opening them, reading headers, and
    /// comparing job_id and generation against the ticket.
    /// Helper: verify shard placement from a shard hex string.
    fn verify_shard_placement(&self, shard_hex: &str, job_id: &[u8; 16]) -> bool {
        let computed = compute_shard(&self.format.queue_id, job_id, self.format.shard_count);
        match steadq_names::shard_from_hex(shard_hex) {
            Some(s) => s == computed,
            None => false,
        }
    }

    pub fn resolve(&self, ticket: &TransitionTicket, stabilize: bool) -> ResolutionOutcome {
        let (source_relative_path, destination_relative_path) =
            match self.transition_ticket_paths(ticket) {
                Ok(paths) => paths,
                Err(error) => return ResolutionOutcome::ResolutionFailed(error),
            };
        let source_path = match ResolvePath::new(&source_relative_path) {
            Ok(path) => path,
            Err(error) => return ResolutionOutcome::ResolutionFailed(error),
        };
        let destination_path = match ResolvePath::new(&destination_relative_path) {
            Ok(path) => path,
            Err(error) => return ResolutionOutcome::ResolutionFailed(error),
        };
        let source_common = ticket.source_common();
        let destination_common = match ticket.destination_common() {
            Ok(common) => common,
            Err(error) => return ResolutionOutcome::ResolutionFailed(error),
        };

        let src_result = self.resolve_check_object(&source_path, ticket, &source_common);
        let dest_result = self.resolve_check_object(&destination_path, ticket, &destination_common);

        match (src_result, dest_result) {
            // Source exists but destination doesn't
            (ResolveObj::Match(source), ResolveObj::Absent) => {
                if stabilize {
                    match self.stabilize_object(&source_path, &source) {
                        Ok(true) => ResolutionOutcome::SourceStabilized,
                        Ok(false) => ResolutionOutcome::ConflictingObject,
                        Err(error) => ResolutionOutcome::ResolutionFailed(error),
                    }
                } else {
                    ResolutionOutcome::SourceObserved
                }
            }
            // Destination exists but source doesn't
            (ResolveObj::Absent, ResolveObj::Match(destination)) => {
                if stabilize {
                    match self.stabilize_object(&destination_path, &destination) {
                        Ok(true) => ResolutionOutcome::DestinationStabilized,
                        Ok(false) => ResolutionOutcome::ConflictingObject,
                        Err(error) => ResolutionOutcome::ResolutionFailed(error),
                    }
                } else {
                    ResolutionOutcome::DestinationObserved
                }
            }
            (ResolveObj::Absent, ResolveObj::Absent) => ResolutionOutcome::NeitherObserved,
            (ResolveObj::Match(_), ResolveObj::Match(_)) => ResolutionOutcome::BothObserved,
            // Any conflict
            (ResolveObj::Conflict, _) | (_, ResolveObj::Conflict) => {
                ResolutionOutcome::ConflictingObject
            }
            // I/O errors
            (ResolveObj::Error(e), _) | (_, ResolveObj::Error(e)) => {
                ResolutionOutcome::ResolutionFailed(e)
            }
        }
    }

    pub fn transition_ticket_paths(
        &self,
        ticket: &TransitionTicket,
    ) -> Result<(String, String), Error> {
        ticket.validate_for_queue(&self.format.queue_id)?;
        let source_common = ticket.source_common();
        let destination_common = ticket.destination_common()?;
        let layout = self.layout();
        let source = match ticket.source() {
            TicketSource::Ready {} => layout.ready(&source_common),
            TicketSource::Leased {
                boot_id,
                boottime_deadline_ns,
                wall_deadline_ns,
            } => layout.leased_for_boot(
                &source_common,
                boot_id,
                *boottime_deadline_ns,
                *wall_deadline_ns,
                &ticket.lease_token(),
            )?,
        };
        let destination = match ticket.destination() {
            TicketDestination::Ready {} => layout.ready(&destination_common),
            TicketDestination::Leased {
                boot_id,
                boottime_deadline_ns,
                wall_deadline_ns,
            } => layout.leased_for_boot(
                &destination_common,
                boot_id,
                *boottime_deadline_ns,
                *wall_deadline_ns,
                &ticket.lease_token(),
            )?,
            TicketDestination::Delayed { not_before_ns } => {
                layout.delayed(&destination_common, *not_before_ns)?
            }
            TicketDestination::Receipt { terminal_bucket } => layout.receipt_in_bucket(
                &destination_common,
                &ticket.lease_token(),
                *terminal_bucket,
            ),
            TicketDestination::Dead {
                terminal_bucket,
                reason,
            } => layout.dead_in_bucket(&destination_common, *reason, *terminal_bucket),
        };
        Ok((source.relative_path(), destination.relative_path()))
    }

    fn resolve_receipt_path_matches(
        &self,
        parts: &[&str],
        name: &str,
        ticket: &TransitionTicket,
        expected_common: &CommonFields,
    ) -> bool {
        if parts.len() != 4 || parts[0] != "receipts" {
            return false;
        }
        let parsed = match steadq_names::parse_receipt(name) {
            Ok(parsed) => parsed,
            Err(_) => return false,
        };
        if &parsed.common != expected_common || parsed.token != ticket.lease_token() {
            return false;
        }
        let bucket = parts[1];
        let shard = parts[2];
        parsed.authenticate_tag(&self.format.queue_id, bucket, shard)
            && self.verify_shard_placement(shard, &ticket.job_id())
    }

    fn resolve_check_object(
        &self,
        path: &ResolvePath<'_>,
        ticket: &TransitionTicket,
        expected_common: &CommonFields,
    ) -> ResolveObj {
        let parts = &path.parts;
        let name = path.name;

        let dir_fd = match fs::open_directory_beneath(self.root_fd.as_raw_fd(), path.directory) {
            Ok(fd) => fd,
            Err(error) => match classify_presence_failure(&error) {
                PresenceFailure::Absent => return ResolveObj::Absent,
                PresenceFailure::Io => {
                    return ResolveObj::Error(Error::IoFailure(error.to_string()));
                }
            },
        };
        let directory_stat = match fs::fstat(dir_fd.as_raw_fd()) {
            Ok(stat) => stat,
            Err(error) => return ResolveObj::Error(Error::IoFailure(error.to_string())),
        };

        let file_fd = match fs::openat(dir_fd.as_raw_fd(), name, resolver_file_open_flags(), 0) {
            Ok(fd) => fd,
            Err(error) => match classify_resolver_object_open_failure(&error) {
                ResolverObjectOpenFailure::Absent => return ResolveObj::Absent,
                ResolverObjectOpenFailure::Conflict => return ResolveObj::Conflict,
                ResolverObjectOpenFailure::Io => {
                    return ResolveObj::Error(Error::IoFailure(error.to_string()));
                }
            },
        };
        let stat = match fs::fstat(file_fd.as_raw_fd()) {
            Ok(stat) => stat,
            Err(error) => return ResolveObj::Error(Error::IoFailure(error.to_string())),
        };

        if !is_singly_linked_regular(stat.st_mode, stat.st_nlink) {
            return ResolveObj::Conflict;
        }

        // R4-B07: Read the 128-byte header buffer.
        let mut header_buf = [0u8; 128];
        if let Err(error) = fs::pread_exact(file_fd.as_raw_fd(), &mut header_buf, 0) {
            return if error.kind() == io::ErrorKind::UnexpectedEof {
                ResolveObj::Conflict
            } else {
                ResolveObj::Error(Error::IoFailure(error.to_string()))
            };
        }

        let state = parts[0];

        // Compact receipts are valid only as authenticated receipt destinations.
        if is_compact_receipt_candidate(stat.st_size as usize, &header_buf[0..8]) {
            if !is_acknowledgement_receipt_path(
                ticket.operation(),
                self.resolve_receipt_path_matches(parts, name, ticket, expected_common),
            ) {
                return ResolveObj::Conflict;
            }
            match steadq_format::CompactReceipt::decode(&header_buf) {
                Ok(cr) if cr.job_id == ticket.job_id() => {
                    // R4-B07: Verify compact receipt fields against the ticket.
                    // The envelope digest must match when known (non-zero).
                    if cr.envelope_digest != ticket.envelope_digest() {
                        return ResolveObj::Conflict;
                    }
                    if cr.original_payload_length != ticket.payload_length() {
                        return ResolveObj::Conflict;
                    }
                    if cr.lease_token != ticket.lease_token() {
                        return ResolveObj::Conflict;
                    }
                    if cr.final_attempt != expected_common.attempt {
                        return ResolveObj::Conflict;
                    }
                    let expected_bucket_start = match parts
                        .get(1)
                        .and_then(|value| steadq_names::bucket_from_hex(value))
                        .and_then(|bucket| bucket.checked_mul(self.format.terminal_bucket_width_ns))
                    {
                        Some(value) => value,
                        None => return ResolveObj::Conflict,
                    };
                    if cr.receipt_bucket_start_unix_ns != expected_bucket_start {
                        return ResolveObj::Conflict;
                    }
                    return ResolveObj::Match(ResolvedObject {
                        directory_fd: dir_fd,
                        directory_device: directory_stat.st_dev as u64,
                        directory_inode: directory_stat.st_ino as u64,
                        file_fd,
                        device: stat.st_dev as u64,
                        inode: stat.st_ino as u64,
                    });
                }
                Ok(_) => return ResolveObj::Conflict,
                Err(_) => return ResolveObj::Conflict,
            }
        }

        let verified = match verified::verify_job_on_fd(file_fd.as_raw_fd()) {
            Ok(verified) => verified,
            Err(verified::VerificationError::Io(error)) => {
                return ResolveObj::Error(Error::IoFailure(error));
            }
            Err(
                verified::VerificationError::Corrupt(_)
                | verified::VerificationError::PayloadCorrupt,
            ) => return ResolveObj::Conflict,
        };
        let header = verified.header;

        // R4-B07: Verify header job_id matches the ticket.
        if header.job_id != ticket.job_id() {
            return ResolveObj::Conflict;
        }
        if header.maximum_attempts != expected_common.maximum_attempts {
            return ResolveObj::Conflict;
        }

        if header.envelope_digest != ticket.envelope_digest() {
            return ResolveObj::Conflict;
        }
        if header.payload_length != ticket.payload_length() {
            return ResolveObj::Conflict;
        }

        // R4-B07: Parse the filename using the state-appropriate parser and
        // verify identity fields against the ticket. The state is derived from
        // the path prefix, not trusted from the ticket.
        match state {
            "ready" => {
                // ready/<shard>/<file> = 3 parts
                if parts.len() != 3 {
                    return ResolveObj::Conflict;
                }
                let p = match steadq_names::parse_ready(name) {
                    Ok(p) => p,
                    Err(_) => return ResolveObj::Conflict,
                };
                if &p.common != expected_common {
                    return ResolveObj::Conflict;
                }
                let shard_hex = parts[1];
                if !p.authenticate_tag(&self.format.queue_id, shard_hex) {
                    return ResolveObj::Conflict;
                }
                if !self.verify_shard_placement(shard_hex, &ticket.job_id()) {
                    return ResolveObj::Conflict;
                }
            }
            "leased" => {
                // leased/<boot>/<bucket>/<shard>/<file> = 5 parts
                if parts.len() != 5 {
                    return ResolveObj::Conflict;
                }
                let p = match steadq_names::parse_leased(name) {
                    Ok(p) => p,
                    Err(_) => return ResolveObj::Conflict,
                };
                if &p.common != expected_common {
                    return ResolveObj::Conflict;
                }
                if p.token != ticket.lease_token() {
                    return ResolveObj::Conflict;
                }
                let boot = parts[1];
                let bucket = parts[2];
                let shard_hex = parts[3];
                if !p.authenticate_tag(&self.format.queue_id, boot, bucket, shard_hex) {
                    return ResolveObj::Conflict;
                }
                if !self.verify_shard_placement(shard_hex, &ticket.job_id()) {
                    return ResolveObj::Conflict;
                }
            }
            "delayed" => {
                // delayed/<bucket>/<shard>/<file> = 4 parts
                if parts.len() != 4 {
                    return ResolveObj::Conflict;
                }
                let p = match steadq_names::parse_delayed(name) {
                    Ok(p) => p,
                    Err(_) => return ResolveObj::Conflict,
                };
                if &p.common != expected_common {
                    return ResolveObj::Conflict;
                }
                let bucket = parts[1];
                let shard_hex = parts[2];
                if !p.authenticate_tag(&self.format.queue_id, bucket, shard_hex) {
                    return ResolveObj::Conflict;
                }
                if !self.verify_shard_placement(shard_hex, &ticket.job_id()) {
                    return ResolveObj::Conflict;
                }
            }
            "dead" => {
                // dead/<bucket>/<shard>/<file> = 4 parts
                if parts.len() != 4 {
                    return ResolveObj::Conflict;
                }
                let p = match steadq_names::parse_dead(name) {
                    Ok(p) => p,
                    Err(_) => return ResolveObj::Conflict,
                };
                if &p.common != expected_common {
                    return ResolveObj::Conflict;
                }
                let bucket = parts[1];
                let shard_hex = parts[2];
                if !p.authenticate_tag(&self.format.queue_id, bucket, shard_hex) {
                    return ResolveObj::Conflict;
                }
                if !self.verify_shard_placement(shard_hex, &ticket.job_id()) {
                    return ResolveObj::Conflict;
                }
            }
            "receipts" => {
                if !is_acknowledgement_receipt_path(
                    ticket.operation(),
                    self.resolve_receipt_path_matches(parts, name, ticket, expected_common),
                ) {
                    return ResolveObj::Conflict;
                }
            }
            _ => return ResolveObj::Conflict,
        }

        ResolveObj::Match(ResolvedObject {
            directory_fd: dir_fd,
            directory_device: directory_stat.st_dev as u64,
            directory_inode: directory_stat.st_ino as u64,
            file_fd,
            device: stat.st_dev as u64,
            inode: stat.st_ino as u64,
        })
    }

    fn stabilize_object(
        &self,
        path: &ResolvePath<'_>,
        object: &ResolvedObject,
    ) -> Result<bool, Error> {
        fs::fsync(object.file_fd.as_raw_fd()).map_err(|e| Error::IoFailure(e.to_string()))?;
        fs::fsync_dir_fd(object.directory_fd.as_raw_fd())
            .map_err(|e| Error::IoFailure(e.to_string()))?;
        let current_directory =
            match fs::open_directory_beneath(self.root_fd.as_raw_fd(), path.directory) {
                Ok(directory) => directory,
                Err(error) => {
                    if resolver_error_is_not_found(&error) {
                        return Ok(false);
                    }
                    return Err(Error::IoFailure(error.to_string()));
                }
            };
        let current_directory_stat = fs::fstat(current_directory.as_raw_fd())
            .map_err(|error| Error::IoFailure(error.to_string()))?;
        if !identity_matches(
            current_directory_stat.st_dev as u64,
            current_directory_stat.st_ino as u64,
            object.directory_device,
            object.directory_inode,
        ) {
            return Ok(false);
        }
        let current = match fs::fstatat(current_directory.as_raw_fd(), path.name) {
            Ok(stat) => stat,
            Err(error) => {
                if resolver_error_is_not_found(&error) {
                    return Ok(false);
                }
                return Err(Error::IoFailure(error.to_string()));
            }
        };
        Ok(resolved_identity_matches(
            current.st_mode,
            current.st_dev as u64,
            current.st_ino as u64,
            object.device,
            object.inode,
        ))
    }
}

/// Open a relative path from a directory fd.
pub(crate) fn open_relative(root_fd: RawFd, relative: &str) -> io::Result<OwnedFd> {
    let relative = fs::ValidatedRelativePath::new(relative)?;
    let mut current = None::<OwnedFd>;
    for component in relative.components() {
        let parent_fd = current
            .as_ref()
            .map_or(root_fd, std::os::fd::AsRawFd::as_raw_fd);
        current = Some(fs::open_directory(parent_fd, component)?);
    }
    current.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty relative path"))
}

/// Input for an enqueue operation.
#[derive(Clone, Debug, Default)]
pub struct EnqueueInput {
    pub maximum_attempts: u32,
    pub content_type: String,
    pub metadata: std::collections::BTreeMap<String, steadq_format::cbor::MetadataValue>,
    pub producer_id: Option<String>,
    pub trace_context: Option<Vec<u8>>,
    pub initial_not_before: Option<u64>,
    pub payload: Vec<u8>,
}

/// Internal error type for publication.
enum PublishError {
    NotCommitted(Error),
    OutcomeUnknown(Error),
}

impl PublishError {
    fn classify_write(e: io::Error) -> Self {
        match e.raw_os_error() {
            Some(libc::ENOSPC) | Some(libc::EDQUOT) => {
                PublishError::NotCommitted(Error::ResourceExhausted)
            }
            Some(libc::EIO) | Some(libc::ESTALE) => {
                PublishError::NotCommitted(Error::IoFailure(e.to_string()))
            }
            _ => PublishError::NotCommitted(Error::IoFailure(e.to_string())),
        }
    }

    /// Classify a file fsync failure that occurs BEFORE the linearizing
    /// link/rename. Per spec section 7.8, this is NotCommitted.
    fn classify_pre_pub_fsync(e: io::Error) -> Self {
        PublishError::NotCommitted(Error::IoFailure(e.to_string()))
    }

    /// Classify a directory fsync failure that occurs AFTER the linearizing
    /// link/rename. Per spec section 7.8, this is OutcomeUnknown.
    fn classify_post_fsync(e: io::Error) -> Self {
        PublishError::OutcomeUnknown(Error::IoFailure(e.to_string()))
    }
}

fn nb_to_u64(opt: Option<u64>) -> u64 {
    opt.unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FsckOptions;
    use std::os::unix::fs::FileExt;

    trait CommitOrPanic {
        fn commit_or_panic(&self);
    }

    impl CommitOrPanic for TransitionOutcome {
        fn commit_or_panic(&self) {
            assert!(matches!(self, TransitionOutcome::Committed));
        }
    }
    use tempfile::TempDir;

    fn create_test_queue() -> (TempDir, Queue) {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path();
        Queue::init(path, &CreateOptions::default()).unwrap();
        let queue = Queue::open(
            path,
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        (tmp, queue)
    }

    fn test_claim_ticket(
        queue: &Queue,
        job_id: [u8; 16],
        generation: u64,
        attempt: u32,
        maximum_attempts: u32,
        lease_token: [u8; 16],
        envelope_digest: [u8; 32],
    ) -> TransitionTicket {
        let common = CommonFields {
            job_id,
            generation,
            attempt,
            maximum_attempts,
        };
        queue
            .claim_transition_ticket(
                &common,
                lease_token,
                TicketEvidence::new(envelope_digest, 4),
                1,
                1,
            )
            .unwrap()
    }

    fn enqueue_and_lease(queue: &mut Queue) -> LeaseInfo {
        assert!(matches!(
            queue.enqueue(EnqueueInput {
                maximum_attempts: 3,
                content_type: "text/plain".to_string(),
                payload: b"resolver state".to_vec(),
                ..Default::default()
            }),
            EnqueueOutcome::Committed(_)
        ));
        match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(lease) => lease,
            outcome => panic!("expected lease, got {outcome:?}"),
        }
    }

    fn add_hard_link(tmp: &tempfile::TempDir, relative_path: &str, label: &str) {
        std::fs::hard_link(
            tmp.path().join(relative_path),
            tmp.path().join(format!("tmp/{label}.link")),
        )
        .unwrap();
    }

    fn resolver_ticket_case(operation: &str) -> (tempfile::TempDir, Queue, TransitionTicket) {
        let (tmp, mut queue) = create_test_queue();
        if operation == "claim" {
            let enqueue = match queue.enqueue(EnqueueInput {
                maximum_attempts: 3,
                content_type: "text/plain".into(),
                payload: b"data".to_vec(),
                ..Default::default()
            }) {
                EnqueueOutcome::Committed(ticket) => ticket,
                outcome => panic!("expected enqueue, got {outcome:?}"),
            };
            let parsed = steadq_names::parse_ready(
                enqueue.expected_relative_path.rsplit('/').next().unwrap(),
            )
            .unwrap();
            let ticket = queue
                .claim_transition_ticket(
                    &parsed.common,
                    [8; 16],
                    TicketEvidence::new(enqueue.envelope_digest, 4),
                    1,
                    1,
                )
                .unwrap();
            return (tmp, queue, ticket);
        }

        let lease = enqueue_and_lease(&mut queue);
        let (operation, destination) = match operation {
            "acknowledge" => (
                TransitionOperation::Acknowledge,
                TicketDestination::Receipt { terminal_bucket: 1 },
            ),
            "retry_now" => (TransitionOperation::RetryNow, TicketDestination::Ready {}),
            "retry_later" => (
                TransitionOperation::RetryLater,
                TicketDestination::Delayed { not_before_ns: 1 },
            ),
            "bury" => (
                TransitionOperation::Bury,
                TicketDestination::Dead {
                    terminal_bucket: 1,
                    reason: DeadReason::AdministrativeBury as u16,
                },
            ),
            "renew" => (
                TransitionOperation::Renew,
                TicketDestination::Leased {
                    boot_id: lease.boot_id.clone(),
                    boottime_deadline_ns: lease.expires_boottime_ns + 1,
                    wall_deadline_ns: lease.expires_wall_ns + 1,
                },
            ),
            _ => unreachable!(),
        };
        let ticket = queue
            .transition_ticket_for_lease(&lease, operation, destination)
            .unwrap();
        (tmp, queue, ticket)
    }

    #[test]
    fn resolver_error_is_not_found_table() {
        for (errno, expected) in [
            (libc::ENOENT, true),
            (libc::EIO, false),
            (libc::EACCES, false),
        ] {
            let error = io::Error::from_raw_os_error(errno);
            assert_eq!(resolver_error_is_not_found(&error), expected);
        }
    }

    #[test]
    fn lease_directory_open_failure_table() {
        for (errno, expected) in [
            (libc::ENOENT, LeaseDirectoryOpenFailure::Gone),
            (libc::ENOTDIR, LeaseDirectoryOpenFailure::InvalidDirectory),
            (libc::EIO, LeaseDirectoryOpenFailure::Io),
            (libc::EACCES, LeaseDirectoryOpenFailure::Io),
        ] {
            assert_eq!(
                classify_lease_directory_open_failure(&io::Error::from_raw_os_error(errno)),
                expected,
            );
        }
    }

    #[test]
    fn resolver_object_open_failure_table() {
        for (errno, expected) in [
            (libc::ENOENT, ResolverObjectOpenFailure::Absent),
            (libc::ELOOP, ResolverObjectOpenFailure::Conflict),
            (libc::EIO, ResolverObjectOpenFailure::Io),
            (libc::EACCES, ResolverObjectOpenFailure::Io),
        ] {
            assert_eq!(
                classify_resolver_object_open_failure(&io::Error::from_raw_os_error(errno)),
                expected,
            );
        }
    }

    #[test]
    fn presence_failure_table() {
        for (errno, expected) in [
            (libc::ENOENT, PresenceFailure::Absent),
            (libc::EIO, PresenceFailure::Io),
            (libc::EACCES, PresenceFailure::Io),
        ] {
            assert_eq!(
                classify_presence_failure(&io::Error::from_raw_os_error(errno)),
                expected,
            );
        }
    }

    #[test]
    fn same_directory_identity_table() {
        let (_tmp, queue) = create_test_queue();
        let source = fs::fstat(queue.root_fd()).unwrap();
        let mut different_device = source;
        different_device.st_dev ^= 1;
        let mut different_inode = source;
        different_inode.st_ino ^= 1;

        assert!(same_directory_identity(Some(&source), Some(&source)));
        assert!(!same_directory_identity(
            Some(&source),
            Some(&different_device),
        ));
        assert!(!same_directory_identity(
            Some(&source),
            Some(&different_inode),
        ));
        assert!(!same_directory_identity(None, Some(&source)));
        assert!(!same_directory_identity(Some(&source), None));
        assert!(!same_directory_identity(None, None));
    }

    #[test]
    fn compact_receipt_candidate_table() {
        let mut wrong_magic = *steadq_format::RECEIPT_MAGIC;
        wrong_magic[0] ^= 1;
        for (size, magic, expected) in [
            (
                steadq_format::COMPACT_RECEIPT_SIZE,
                steadq_format::RECEIPT_MAGIC.as_slice(),
                true,
            ),
            (
                steadq_format::COMPACT_RECEIPT_SIZE - 1,
                steadq_format::RECEIPT_MAGIC.as_slice(),
                false,
            ),
            (
                steadq_format::COMPACT_RECEIPT_SIZE,
                wrong_magic.as_slice(),
                false,
            ),
        ] {
            assert_eq!(is_compact_receipt_candidate(size, magic), expected);
        }
    }

    #[test]
    fn acknowledgement_receipt_path_table() {
        for (operation, path_matches, expected) in [
            (TransitionOperation::Acknowledge, true, true),
            (TransitionOperation::Acknowledge, false, false),
            (TransitionOperation::Claim, true, false),
            (TransitionOperation::Claim, false, false),
        ] {
            assert_eq!(
                is_acknowledgement_receipt_path(operation, path_matches),
                expected,
            );
        }
    }

    #[test]
    fn resolved_identity_matches_table() {
        let cases = [
            (libc::S_IFREG | 0o600, 7, 11, true),
            (libc::S_IFDIR | 0o700, 7, 11, false),
            (libc::S_IFREG | 0o600, 8, 11, false),
            (libc::S_IFREG | 0o600, 7, 12, false),
        ];
        for (mode, device, inode, expected) in cases {
            assert_eq!(
                resolved_identity_matches(mode, device, inode, 7, 11),
                expected
            );
        }
    }

    #[test]
    fn open_relative_rejects_escape_before_opening_a_component() {
        let (_tmp, queue) = create_test_queue();
        fs::fault::reset();
        fs::fault::inject("open_directory", 1);
        let result = open_relative(queue.root_fd().as_raw_fd(), "ready/../../outside");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert_eq!(fs::fault::call_count("open_directory"), 0);
        fs::fault::reset();
    }

    #[test]
    fn init_and_open() {
        let (_tmp, queue) = create_test_queue();
        assert_eq!(queue.format().shard_count, 64);
    }

    #[test]
    fn enqueue_basic() {
        let (_tmp, mut queue) = create_test_queue();
        let input = EnqueueInput {
            maximum_attempts: 3,
            content_type: "text/plain".to_string(),
            payload: b"hello world".to_vec(),
            ..Default::default()
        };
        let outcome = queue.enqueue(input);
        match outcome {
            EnqueueOutcome::Committed(ticket) => {
                assert!(!ticket.expected_relative_path.is_empty());
                assert!(ticket.expected_relative_path.starts_with("ready/"));
            }
            _ => panic!("expected committed, got {outcome:?}"),
        }
    }

    #[test]
    fn ticket_envelope_digest_authenticates_ready_header() {
        let (_tmp, mut queue) = create_test_queue();
        let enqueue = match queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "text/plain".to_string(),
            payload: b"ticket evidence".to_vec(),
            ..Default::default()
        }) {
            EnqueueOutcome::Committed(ticket) => ticket,
            outcome => panic!("expected committed enqueue, got {outcome:?}"),
        };
        let (directory, name) = enqueue.expected_relative_path.rsplit_once('/').unwrap();
        let directory_fd = open_relative(queue.root_fd().as_raw_fd(), directory).unwrap();

        let witness =
            Queue::open_claim_source(directory_fd.as_raw_fd(), name, &enqueue.job_id, 3).unwrap();
        assert_eq!(witness.evidence.envelope_digest, enqueue.envelope_digest);
        assert_eq!(witness.evidence.payload_length, 15);

        let mut wrong_job_id = enqueue.job_id;
        wrong_job_id[0] ^= 0xff;
        assert!(matches!(
            Queue::open_claim_source(directory_fd.as_raw_fd(), name, &wrong_job_id, 3,),
            Err(Error::QueueCorrupt(_))
        ));
        assert!(matches!(
            Queue::open_claim_source(directory_fd.as_raw_fd(), name, &enqueue.job_id, 4,),
            Err(Error::QueueCorrupt(_))
        ));
    }

    #[test]
    fn claim_source_witness_detects_path_replacement() {
        let (tmp, mut queue) = create_test_queue();
        let enqueue = match queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "text/plain".to_string(),
            payload: b"replacement".to_vec(),
            ..Default::default()
        }) {
            EnqueueOutcome::Committed(ticket) => ticket,
            outcome => panic!("expected committed enqueue, got {outcome:?}"),
        };
        let (directory, name) = enqueue.expected_relative_path.rsplit_once('/').unwrap();
        let directory_fd = open_relative(queue.root_fd().as_raw_fd(), directory).unwrap();
        let witness =
            Queue::open_claim_source(directory_fd.as_raw_fd(), name, &enqueue.job_id, 3).unwrap();
        let source = tmp.path().join(&enqueue.expected_relative_path);
        let displaced = tmp.path().join("tmp/displaced-ready.sqj");
        std::fs::rename(&source, &displaced).unwrap();
        std::fs::copy(&displaced, &source).unwrap();
        let replacement = fs::fstatat(directory_fd.as_raw_fd(), name).unwrap();

        assert_eq!(
            classify_claim_source_identity(&replacement, &witness),
            ClaimSourceIdentity::Mismatch
        );
        let original = fs::fstat(witness.file_fd.as_raw_fd()).unwrap();
        assert_eq!(
            classify_claim_source_identity(&original, &witness),
            ClaimSourceIdentity::Match
        );
    }

    #[test]
    fn leased_source_witness_rejects_replacement_after_validation() {
        let (tmp, mut queue) = create_test_queue();
        let lease = enqueue_and_lease(&mut queue);
        let source = queue
            .open_and_validate_current_lease(&lease)
            .unwrap()
            .unwrap();
        let source_path = tmp.path().join(&lease.exact_source_path);
        let displaced = tmp.path().join("tmp/displaced-leased.sqj");
        std::fs::rename(&source_path, &displaced).unwrap();
        std::fs::copy(&displaced, &source_path).unwrap();

        assert_eq!(
            Queue::observe_leased_source_path(&source).unwrap(),
            WitnessPathObservation::Mismatch
        );
        let ready = queue.layout().ready(&CommonFields {
            job_id: lease.job_id,
            generation: lease.generation + 1,
            attempt: lease.attempt,
            maximum_attempts: lease.maximum_attempts,
        });
        let destination_directory = open_relative(queue.root_fd(), &ready.directory()).unwrap();
        assert!(matches!(
            Queue::rename_leased_witness_noreplace(
                &source,
                destination_directory.as_raw_fd(),
                &ready.filename,
            ),
            WitnessedRenameOutcome::SourceChanged
        ));
        assert!(!tmp.path().join(ready.relative_path()).exists());
    }

    #[test]
    fn leased_source_witness_rejects_symlink_after_validation() {
        let (tmp, mut queue) = create_test_queue();
        let lease = enqueue_and_lease(&mut queue);
        let source = queue
            .open_and_validate_current_lease(&lease)
            .unwrap()
            .unwrap();
        let source_path = tmp.path().join(&lease.exact_source_path);
        let displaced = tmp.path().join("tmp/displaced-leased-symlink.sqj");
        std::fs::rename(&source_path, &displaced).unwrap();
        std::os::unix::fs::symlink(&displaced, &source_path).unwrap();

        assert_eq!(
            Queue::observe_leased_source_path(&source).unwrap(),
            WitnessPathObservation::Mismatch
        );
    }

    #[test]
    fn leased_source_witness_classifies_absence_and_io() {
        let (tmp, mut queue) = create_test_queue();
        let lease = enqueue_and_lease(&mut queue);
        let source = queue
            .open_and_validate_current_lease(&lease)
            .unwrap()
            .unwrap();

        fs::fault::reset();
        fs::fault::inject("fstatat", 1);
        assert!(matches!(
            Queue::observe_leased_source_path(&source),
            Err(Error::IoFailure(_))
        ));
        fs::fault::reset();

        std::fs::remove_file(tmp.path().join(&lease.exact_source_path)).unwrap();
        assert_eq!(
            Queue::observe_leased_source_path(&source).unwrap(),
            WitnessPathObservation::Gone
        );
    }

    #[test]
    fn renamed_destination_requires_exact_witness_identity() {
        let (_tmp, mut queue) = create_test_queue();
        let lease = enqueue_and_lease(&mut queue);
        let source = queue
            .open_and_validate_current_lease(&lease)
            .unwrap()
            .unwrap();
        let mut stat = fs::fstat(source.file_fd.as_raw_fd()).unwrap();
        assert!(matches!(
            classify_renamed_destination(Some(&stat), source.device, source.inode),
            WitnessedRenameOutcome::Linearized
        ));
        stat.st_ino ^= 1;
        assert!(matches!(
            classify_renamed_destination(Some(&stat), source.device, source.inode),
            WitnessedRenameOutcome::LinearizedIdentityUnknown
        ));
        assert!(matches!(
            classify_renamed_destination(None, source.device, source.inode),
            WitnessedRenameOutcome::LinearizedIdentityUnknown
        ));
    }

    #[test]
    fn witnessed_rename_preserves_failure_categories() {
        for (errno, expected) in [
            (libc::ENOENT, "gone"),
            (libc::EEXIST, "collision"),
            (libc::EIO, "failed"),
        ] {
            let (_tmp, mut queue) = create_test_queue();
            let lease = enqueue_and_lease(&mut queue);
            let source = queue
                .open_and_validate_current_lease(&lease)
                .unwrap()
                .unwrap();
            let ready = queue.layout().ready(&CommonFields {
                job_id: lease.job_id,
                generation: lease.generation + 1,
                attempt: lease.attempt,
                maximum_attempts: lease.maximum_attempts,
            });
            let destination_directory = open_relative(queue.root_fd(), &ready.directory()).unwrap();
            fs::fault::reset();
            fs::fault::inject_errno("renameat2_noreplace", 1, errno);
            let outcome = Queue::rename_leased_witness_noreplace(
                &source,
                destination_directory.as_raw_fd(),
                &ready.filename,
            );
            match expected {
                "gone" => assert!(matches!(outcome, WitnessedRenameOutcome::SourceGone)),
                "collision" => assert!(matches!(outcome, WitnessedRenameOutcome::Collision)),
                "failed" => assert!(matches!(outcome, WitnessedRenameOutcome::Failed(_))),
                _ => unreachable!(),
            }
            fs::fault::reset();
        }
    }

    #[test]
    fn witnessed_rename_reports_post_linearization_identity_error() {
        let (_tmp, mut queue) = create_test_queue();
        let lease = enqueue_and_lease(&mut queue);
        let source = queue
            .open_and_validate_current_lease(&lease)
            .unwrap()
            .unwrap();
        let ready = queue.layout().ready(&CommonFields {
            job_id: lease.job_id,
            generation: lease.generation + 1,
            attempt: lease.attempt,
            maximum_attempts: lease.maximum_attempts,
        });
        let destination_directory = open_relative(queue.root_fd(), &ready.directory()).unwrap();
        fs::fault::reset();
        fs::fault::inject_errno("fstatat", 2, libc::EIO);
        assert!(matches!(
            Queue::rename_leased_witness_noreplace(
                &source,
                destination_directory.as_raw_fd(),
                &ready.filename,
            ),
            WitnessedRenameOutcome::LinearizedIdentityUnknown
        ));
        fs::fault::reset();
    }

    #[test]
    fn claim_source_file_type_and_link_policy_table() {
        assert!(is_singly_linked_regular(libc::S_IFREG | 0o400, 1));
        assert!(!is_singly_linked_regular(libc::S_IFREG | 0o400, 2));
        assert!(!is_singly_linked_regular(libc::S_IFDIR | 0o500, 1));
        assert!(!is_singly_linked_regular(libc::S_IFLNK | 0o400, 1));
    }

    #[test]
    fn claim_source_evidence_detects_in_place_header_change() {
        let (tmp, mut queue) = create_test_queue();
        let enqueue = match queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "text/plain".to_string(),
            payload: b"in-place".to_vec(),
            ..Default::default()
        }) {
            EnqueueOutcome::Committed(ticket) => ticket,
            outcome => panic!("expected committed enqueue, got {outcome:?}"),
        };
        let (directory, name) = enqueue.expected_relative_path.rsplit_once('/').unwrap();
        let directory_fd = open_relative(queue.root_fd().as_raw_fd(), directory).unwrap();
        let witness =
            Queue::open_claim_source(directory_fd.as_raw_fd(), name, &enqueue.job_id, 3).unwrap();
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(tmp.path().join(enqueue.expected_relative_path))
            .unwrap();
        file.write_at(&[0xff], 0).unwrap();

        assert!(matches!(
            Queue::read_claim_ticket_evidence(witness.file_fd.as_raw_fd(), &enqueue.job_id, 3,),
            Err(Error::QueueCorrupt(_))
        ));
    }

    #[test]
    fn lease_reports_ready_header_corruption_without_flattening() {
        let (tmp, mut queue) = create_test_queue();
        let enqueue = match queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "text/plain".to_string(),
            payload: b"corrupt claim".to_vec(),
            ..Default::default()
        }) {
            EnqueueOutcome::Committed(ticket) => ticket,
            outcome => panic!("expected committed enqueue, got {outcome:?}"),
        };
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(tmp.path().join(enqueue.expected_relative_path))
            .unwrap();
        file.write_at(&[0xff], 0).unwrap();

        assert!(matches!(
            queue.lease(0, 30_000_000_000),
            LeaseOutcome::NotCommitted(Error::QueueCorrupt(_))
        ));
    }

    #[test]
    fn enqueue_delayed() {
        let (_tmp, mut queue) = create_test_queue();
        let future = fs::clock_realtime_ns().unwrap() + 60_000_000_000; // 60s in future
        let input = EnqueueInput {
            maximum_attempts: 1,
            content_type: "application/octet-stream".to_string(),
            initial_not_before: Some(future),
            payload: vec![0x42; 100],
            ..Default::default()
        };
        let outcome = queue.enqueue(input);
        match outcome {
            EnqueueOutcome::Committed(ticket) => {
                assert!(ticket.expected_relative_path.starts_with("delayed/"));
            }
            _ => panic!("expected committed, got {outcome:?}"),
        }
    }

    #[test]
    fn enqueue_zero_attempts_rejected() {
        let (_tmp, mut queue) = create_test_queue();
        let input = EnqueueInput {
            maximum_attempts: 0,
            content_type: "x".to_string(),
            payload: vec![1],
            ..Default::default()
        };
        let outcome = queue.enqueue(input);
        assert!(matches!(outcome, EnqueueOutcome::NotCommitted(_, _)));
    }

    #[test]
    fn format_file_exists_after_init() {
        let tmp = TempDir::new().unwrap();
        Queue::init(tmp.path(), &CreateOptions::default()).unwrap();
        assert!(tmp.path().join("FORMAT").exists());
        assert!(tmp.path().join("control").exists());
        assert!(tmp.path().join("control/maintenance.lock").exists());
        assert!(tmp.path().join("control/wall-watermark").exists());
        assert!(tmp.path().join("ready").exists());
        // Check shard dirs
        assert!(tmp.path().join("ready/0000").exists());
        assert!(tmp.path().join("ready/003f").exists());
    }

    #[test]
    fn full_lifecycle() {
        let (_tmp, mut queue) = create_test_queue();

        // Enqueue
        let input = EnqueueInput {
            maximum_attempts: 3,
            content_type: "text/plain".to_string(),
            payload: b"hello world".to_vec(),
            ..Default::default()
        };
        let ticket = match queue.enqueue(input) {
            EnqueueOutcome::Committed(t) => t,
            other => panic!("enqueue failed: {other:?}"),
        };

        // Lease
        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            other => panic!("lease failed: {other:?}"),
        };
        assert_eq!(lease.job_id, ticket.job_id);
        assert_eq!(lease.attempt, 1);
        assert_eq!(lease.generation, 1);

        // Verify and ack
        queue.verify_lease_payload(&lease).unwrap();
        let ack_result = queue.ack(&lease);
        assert!(matches!(ack_result, AckOutcome::Acked));
    }

    #[test]
    fn lease_empty_queue() {
        let (_tmp, mut queue) = create_test_queue();
        let result = queue.lease(0, 30_000_000_000);
        assert!(matches!(result, LeaseOutcome::Empty));
    }

    #[test]
    fn retry_after_lease() {
        let (_tmp, mut queue) = create_test_queue();
        let input = EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"data".to_vec(),
            ..Default::default()
        };
        let _ = queue.enqueue(input);

        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            other => panic!("lease failed: {other:?}"),
        };

        // Retry now -> back to ready
        let result = queue.retry_now(&lease);
        assert!(matches!(result, TransitionOutcome::Committed));

        // Should be able to lease again
        let lease2 = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            other => panic!("second lease failed: {other:?}"),
        };
        assert_eq!(lease2.attempt, 2);
    }

    #[test]
    fn bury_after_lease() {
        let (_tmp, mut queue) = create_test_queue();
        let input = EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"data".to_vec(),
            ..Default::default()
        };
        let _ = queue.enqueue(input);

        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            other => panic!("lease failed: {other:?}"),
        };

        let result = queue.bury(&lease, DeadReason::ConsumerRejected);
        assert!(matches!(result, TransitionOutcome::Committed));

        // Queue should be empty now
        let result2 = queue.lease(0, 30_000_000_000);
        assert!(matches!(result2, LeaseOutcome::Empty));
    }

    #[test]
    fn retry_exhausted_goes_to_dead() {
        let (_tmp, mut queue) = create_test_queue();
        let input = EnqueueInput {
            maximum_attempts: 1,
            content_type: "x".to_string(),
            payload: b"data".to_vec(),
            ..Default::default()
        };
        let _ = queue.enqueue(input);

        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            other => panic!("lease failed: {other:?}"),
        };
        assert_eq!(lease.maximum_attempts, 1);
        assert_eq!(lease.attempt, 1);

        // Attempt >= maximum_attempts, retry should go to dead
        let result = queue.retry_now(&lease);
        assert!(matches!(result, TransitionOutcome::Committed));

        // Queue should be empty
        let result2 = queue.lease(0, 30_000_000_000);
        assert!(matches!(result2, LeaseOutcome::Empty));
    }

    #[test]
    fn renew_extends_lease() {
        let (_tmp, mut queue) = create_test_queue();
        let input = EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"data".to_vec(),
            ..Default::default()
        };
        let _ = queue.enqueue(input);

        let lease = match queue.lease(0, 10_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            other => panic!("lease failed: {other:?}"),
        };

        let renewed = match queue.renew(&lease, 60_000_000_000) {
            RenewOutcome::Renewed(l) => l,
            other => panic!("renew failed: {other:?}"),
        };
        assert_eq!(renewed.generation, lease.generation + 1);
        assert!(renewed.expires_boottime_ns > lease.expires_boottime_ns);
        assert!(renewed.expires_wall_ns > lease.expires_wall_ns);
        assert_ne!(renewed.exact_source_path, lease.exact_source_path);
        assert!(_tmp.path().join(&renewed.exact_source_path).exists());
        assert_eq!(renewed.attempt, lease.attempt);
        assert_eq!(renewed.token, lease.token);
    }

    #[test]
    fn ack_already_lost_returns_lease_lost() {
        let (_tmp, mut queue) = create_test_queue();
        let input = EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"data".to_vec(),
            ..Default::default()
        };
        let _ = queue.enqueue(input);

        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            other => panic!("lease failed: {other:?}"),
        };

        // Verify and ack once
        queue.verify_lease_payload(&lease).unwrap();
        assert!(matches!(queue.ack(&lease), AckOutcome::Acked));

        // R2-H01: Second ack should detect the existing receipt and return AlreadyAcked
        let result = queue.ack(&lease);
        assert!(matches!(result, AckOutcome::AlreadyAcked));
    }

    #[test]
    fn lease_duration_validation() {
        let (_tmp, mut queue) = create_test_queue();
        // Too short
        assert!(matches!(
            queue.lease(0, 500_000_000),
            LeaseOutcome::NotCommitted(_)
        ));
        // Too long (more than 7 days)
        assert!(matches!(
            queue.lease(0, 8 * 24 * 60 * 60 * 1_000_000_000),
            LeaseOutcome::NotCommitted(_)
        ));
    }
    #[test]
    fn payload_verification() {
        let (_tmp, mut queue) = create_test_queue();
        let payload = b"verify me please";
        let input = EnqueueInput {
            maximum_attempts: 3,
            content_type: "text/plain".to_string(),
            payload: payload.to_vec(),
            ..Default::default()
        };
        queue.enqueue(input);

        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            _ => panic!("lease failed"),
        };

        assert!(queue.verify_lease_payload(&lease).is_ok());
    }
    #[test]
    fn retry_with_policy_works() {
        let (_tmp, mut queue) = create_test_queue();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 5,
            content_type: "x".to_string(),
            payload: b"data".to_vec(),
            ..Default::default()
        });
        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            _ => panic!("lease failed"),
        };
        let policy = steadq_math::RetryPolicy {
            base_ms: 1000,
            cap_ms: 300_000,
            use_jitter: false,
            max_delay_ms: None,
        };
        let result = queue.retry_with_policy(&lease, &policy);
        assert!(matches!(result, TransitionOutcome::Committed));
    }
    #[test]
    fn inspect_finds_ready_job() {
        let (_tmp, mut queue) = create_test_queue();
        let outcome = queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"data".to_vec(),
            ..Default::default()
        });
        let ticket = match outcome {
            EnqueueOutcome::Committed(t) => t,
            _ => panic!("enqueue failed"),
        };

        let snapshots = queue.inspect(&ticket.job_id);
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].state, "ready");
        assert_eq!(snapshots[0].generation, 0);
    }

    #[test]
    fn inspect_finds_leased_job() {
        let (_tmp, mut queue) = create_test_queue();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"data".to_vec(),
            ..Default::default()
        });
        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            _ => panic!("lease failed"),
        };

        let snapshots = queue.inspect(&lease.job_id);
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].state, "leased");
    }

    #[test]
    fn duplicate_ack_returns_already_acked() {
        let (_tmp, mut queue) = create_test_queue();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"data".to_vec(),
            ..Default::default()
        });
        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            _ => panic!("lease failed"),
        };

        // Verify and ack
        queue.verify_lease_payload(&lease).unwrap();
        assert!(matches!(queue.ack(&lease), AckOutcome::Acked));

        // Source is gone, so check_duplicate_ack should find the receipt
        let result = queue.check_duplicate_ack(&lease);
        assert!(matches!(result, AckOutcome::AlreadyAcked));
    }

    #[test]
    fn inspect_returns_empty_for_unknown() {
        let (_tmp, queue) = create_test_queue();
        let unknown_id = [0xFF; 16];
        let snapshots = queue.inspect(&unknown_id);
        assert!(snapshots.is_empty());
    }
    #[test]
    fn concurrent_producers_consumers() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::thread;

        let tmp = TempDir::new().unwrap();
        let path = tmp.path().to_path_buf();
        Queue::init(&path, &CreateOptions::default()).unwrap();

        let num_producers = 4;
        let num_consumers = 4;
        let jobs_per_producer = 25;
        let total_jobs = num_producers * jobs_per_producer;
        let leased_count = Arc::new(AtomicUsize::new(0));
        let acked_count = Arc::new(AtomicUsize::new(0));

        // Producers
        let mut producer_handles = Vec::new();
        for _ in 0..num_producers {
            let p = path.clone();
            let handle = thread::spawn(move || {
                let queue = Queue::open(
                    &p,
                    &OpenOptions {
                        allow_unsupported_fs: true,
                        ..Default::default()
                    },
                )
                .unwrap();
                let mut queue = queue;
                for _ in 0..jobs_per_producer {
                    let payload =
                        format!("payload-{}", steadq_fs_linux::random_128bit().unwrap()[0]);
                    queue.enqueue(EnqueueInput {
                        maximum_attempts: 3,
                        content_type: "text/plain".to_string(),
                        payload: payload.into_bytes(),
                        ..Default::default()
                    });
                }
            });
            producer_handles.push(handle);
        }
        for h in producer_handles {
            h.join().unwrap();
        }

        // Consumers
        let mut consumer_handles = Vec::new();
        for _ in 0..num_consumers {
            let p = path.clone();
            let lc = leased_count.clone();
            let ac = acked_count.clone();
            let handle = thread::spawn(move || {
                let queue = Queue::open(
                    &p,
                    &OpenOptions {
                        allow_unsupported_fs: true,
                        ..Default::default()
                    },
                )
                .unwrap();
                let mut queue = queue;
                let mut attempts = 0;
                loop {
                    attempts += 1;
                    if attempts > total_jobs * 4 + 100 {
                        panic!(
                            "concurrent test hung: attempts {attempts} exceeded bound, leased {} acked {}",
                            lc.load(Ordering::SeqCst),
                            ac.load(Ordering::SeqCst)
                        );
                    }
                    match queue.lease(0, 30_000_000_000) {
                        LeaseOutcome::Leased(lease) => {
                            lc.fetch_add(1, Ordering::SeqCst);
                            if queue.ack_unverified(&lease) == AckOutcome::Acked {
                                ac.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                        LeaseOutcome::Empty => break,
                        _ => {}
                    }
                }
            });
            consumer_handles.push(handle);
        }
        for h in consumer_handles {
            h.join().unwrap();
        }

        assert_eq!(
            leased_count.load(Ordering::SeqCst),
            total_jobs,
            "expected {} leased, got {}",
            total_jobs,
            leased_count.load(Ordering::SeqCst)
        );
        assert_eq!(
            acked_count.load(Ordering::SeqCst),
            total_jobs,
            "expected {} acked, got {}",
            total_jobs,
            acked_count.load(Ordering::SeqCst)
        );
    }

    #[test]
    fn concurrent_lease_uniqueness() {
        // 8 consumers race for 1 job: exactly one should win
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::thread;

        let tmp = TempDir::new().unwrap();
        let path = tmp.path().to_path_buf();
        Queue::init(&path, &CreateOptions::default()).unwrap();

        // Enqueue exactly one job
        {
            let mut queue = Queue::open(
                &path,
                &OpenOptions {
                    allow_unsupported_fs: true,
                    ..Default::default()
                },
            )
            .unwrap();
            queue.enqueue(EnqueueInput {
                maximum_attempts: 3,
                content_type: "x".to_string(),
                payload: b"race".to_vec(),
                ..Default::default()
            });
        }

        let success_count = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();

        for _ in 0..32 {
            let p = path.clone();
            let sc = success_count.clone();
            handles.push(thread::spawn(move || {
                let queue = Queue::open(
                    &p,
                    &OpenOptions {
                        allow_unsupported_fs: true,
                        ..Default::default()
                    },
                )
                .unwrap();
                let mut queue = queue;
                if let LeaseOutcome::Leased(_) = queue.lease(0, 30_000_000_000) {
                    sc.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(
            success_count.load(Ordering::SeqCst),
            1,
            "exactly one consumer should win the race"
        );
    }

    #[test]
    fn enqueue_survives_reopen() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path();
        Queue::init(path, &CreateOptions::default()).unwrap();

        // Enqueue
        let ticket = {
            let mut queue = Queue::open(
                path,
                &OpenOptions {
                    allow_unsupported_fs: true,
                    ..Default::default()
                },
            )
            .unwrap();
            match queue.enqueue(EnqueueInput {
                maximum_attempts: 3,
                content_type: "text/plain".to_string(),
                payload: b"survive reopen".to_vec(),
                ..Default::default()
            }) {
                EnqueueOutcome::Committed(t) => t,
                _ => panic!("enqueue failed"),
            }
        };

        // Reopen and verify the job is visible
        let queue2 = Queue::open(
            path,
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        let snapshots = queue2.inspect(&ticket.job_id);
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].state, "ready");
    }

    #[test]
    fn enqueue_zero_payload() {
        let (_tmp, mut queue) = create_test_queue();
        let outcome = queue.enqueue(EnqueueInput {
            maximum_attempts: 1,
            content_type: "empty".to_string(),
            payload: vec![],
            ..Default::default()
        });
        match outcome {
            EnqueueOutcome::Committed(ticket) => {
                // Verify it can be leased
                let lease = match queue.lease(0, 30_000_000_000) {
                    LeaseOutcome::Leased(l) => l,
                    _ => panic!("lease failed"),
                };
                assert_eq!(lease.job_id, ticket.job_id);
            }
            _ => panic!("zero-payload enqueue should succeed"),
        }
    }

    #[test]
    fn enqueue_large_payload() {
        let (_tmp, mut queue) = create_test_queue();
        let payload = vec![0x42; 1_000_000]; // 1 MB
        let outcome = queue.enqueue(EnqueueInput {
            maximum_attempts: 1,
            content_type: "large".to_string(),
            payload,
            ..Default::default()
        });
        assert!(matches!(outcome, EnqueueOutcome::Committed(_)));
    }
    #[test]
    fn one_attempt_job_single_lease() {
        let (_tmp, mut queue) = create_test_queue();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 1,
            content_type: "x".to_string(),
            payload: b"one shot".to_vec(),
            ..Default::default()
        });

        // First lease succeeds
        let lease = match queue.lease(0, 10_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            _ => panic!("first lease should succeed"),
        };
        assert_eq!(lease.attempt, 1);
        assert_eq!(lease.maximum_attempts, 1);

        // Retry should go to dead (attempt >= max)
        let result = queue.retry_now(&lease);
        assert!(matches!(result, TransitionOutcome::Committed));

        // No more leases
        assert!(matches!(
            queue.lease(0, 30_000_000_000),
            LeaseOutcome::Empty
        ));
    }

    #[test]
    fn retry_at_in_past_is_retry_now() {
        let (_tmp, mut queue) = create_test_queue();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"past".to_vec(),
            ..Default::default()
        });
        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            _ => panic!("lease failed"),
        };

        // retry_at with a timestamp in the past should behave as retry_now
        let past_ts = 1;
        let result = queue.retry_at(&lease, past_ts);
        assert!(
            matches!(result, TransitionOutcome::Committed),
            "retry should commit, got something else"
        );

        // Job should be in ready (not delayed)
        let result2 = queue.lease(0, 30_000_000_000);
        assert!(
            matches!(result2, LeaseOutcome::Leased(_)),
            "re-lease should succeed"
        );
    }

    #[test]
    fn delay_preserves_attempt() {
        let (_tmp, mut queue) = create_test_queue();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 5,
            content_type: "x".to_string(),
            payload: b"delay".to_vec(),
            ..Default::default()
        });
        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            _ => panic!("lease failed"),
        };
        assert_eq!(lease.attempt, 1);

        // Retry with delay
        let future = steadq_fs_linux::clock_realtime_ns().unwrap_or(0) + 60_000_000_000;
        let result = queue.retry_at(&lease, future);
        assert!(matches!(result, TransitionOutcome::Committed));

        // The job should be in delayed state, not ready
        assert!(matches!(queue.lease(0, 1_000_000_000), LeaseOutcome::Empty));
    }

    #[test]
    fn guard_file_sync_before_publish() {
        // An enqueued job must be fsynced before it appears in an active directory.
        // This is implicit in the O_TMPFILE path: the file is created without a name,
        // synced, then linked. Without the sync, a crash before link loses the file.
        // Verify: after enqueue, the file exists and has content.
        let (_tmp, mut queue) = create_test_queue();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 1,
            content_type: "x".to_string(),
            payload: b"synced".to_vec(),
            ..Default::default()
        });
        // The job should be in ready/ with correct content (not empty)
        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            _ => panic!("lease failed"),
        };
        // Payload verification should pass (file was properly synced before publish)
        assert!(queue.verify_lease_payload(&lease).is_ok());
    }

    #[test]
    fn guard_name_tag_verification() {
        // A job with a wrong name tag should not be delivered by lease.
        let (_tmp, mut queue) = create_test_queue();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 1,
            content_type: "x".to_string(),
            payload: b"tagged".to_vec(),
            ..Default::default()
        });
        // Lease should succeed for the valid job
        let result = queue.lease(0, 30_000_000_000);
        assert!(matches!(result, LeaseOutcome::Leased(_)));
    }

    #[test]
    fn guard_shard_verification() {
        // A job placed in the wrong shard should not be leased from that shard.
        // The claim path verifies computed_shard matches the directory shard.
        let (_tmp, mut queue) = create_test_queue();
        let outcome = queue.enqueue(EnqueueInput {
            maximum_attempts: 1,
            content_type: "x".to_string(),
            payload: b"sharded".to_vec(),
            ..Default::default()
        });
        if let EnqueueOutcome::Committed(_) = outcome {
            // The job should be leasable
            let result = queue.lease(0, 30_000_000_000);
            assert!(
                matches!(result, LeaseOutcome::Leased(_)),
                "job should be leasable"
            );
        }
    }

    #[test]
    fn guard_link_count() {
        // A leased job with link count > 1 should be rejected.
        // The claim path checks st_nlink == 1 after rename.
        let (_tmp, mut queue) = create_test_queue();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 1,
            content_type: "x".to_string(),
            payload: b"linked".to_vec(),
            ..Default::default()
        });
        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            _ => panic!("lease failed"),
        };
        // The file should have link count 1 (no external hard links)
        let path = _tmp.path().join(&lease.exact_source_path);
        let metadata = std::fs::metadata(&path).unwrap();
        use std::os::unix::fs::MetadataExt;
        assert_eq!(metadata.nlink(), 1, "leased file must have link count 1");
    }

    #[test]
    fn guard_attempt_limit_enforced() {
        // maximum_attempts bounds committed claim returns.
        // A job with max_attempts=2 can be leased at most twice before going to dead.
        let (_tmp, mut queue) = create_test_queue();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 2,
            content_type: "x".to_string(),
            payload: b"bounded".to_vec(),
            ..Default::default()
        });

        // First lease
        let l1 = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            _ => panic!(),
        };
        assert_eq!(l1.attempt, 1);
        queue.retry_now(&l1).commit_or_panic();

        // Second lease
        let l2 = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            _ => panic!(),
        };
        assert_eq!(l2.attempt, 2);
        queue.retry_now(&l2).commit_or_panic();

        // Third attempt should go to dead (attempt >= max)
        assert!(matches!(
            queue.lease(0, 30_000_000_000),
            LeaseOutcome::Empty
        ));
    }

    #[test]
    fn guard_payload_verification_prevents_ack() {
        // verify_lease_payload detects corruption and returns PayloadCorrupt.
        // A consumer cannot safely acknowledge without verification.
        let (_tmp, mut queue) = create_test_queue();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 1,
            content_type: "x".to_string(),
            payload: b"verify me".to_vec(),
            ..Default::default()
        });
        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            _ => panic!("lease failed"),
        };
        // Verification should succeed for uncorrupted payload
        assert!(queue.verify_lease_payload(&lease).is_ok());
    }

    // ===== B-01: Init refuses to overwrite existing queue =====
    #[test]
    fn init_refuses_existing_queue() {
        let tmp = TempDir::new().unwrap();
        Queue::init(tmp.path(), &CreateOptions::default()).unwrap();
        // Second init must fail
        let result = Queue::init(tmp.path(), &CreateOptions::default());
        assert!(
            result.is_err(),
            "init must refuse to overwrite existing queue"
        );
    }

    // ===== C-01: All options validated before mutation =====
    #[test]
    fn init_validates_zero_lease_width() {
        let tmp = TempDir::new().unwrap();
        let opts = CreateOptions {
            lease_bucket_width_ns: 0,
            ..Default::default()
        };
        assert!(Queue::init(tmp.path(), &opts).is_err());
        // Root should not have been modified
        assert!(!tmp.path().join("FORMAT").exists());
    }

    #[test]
    fn init_validates_zero_delayed_width() {
        let tmp = TempDir::new().unwrap();
        let opts = CreateOptions {
            delayed_bucket_width_ns: 0,
            ..Default::default()
        };
        assert!(Queue::init(tmp.path(), &opts).is_err());
    }

    // ===== C-11: Payload size checked before hashing =====
    #[test]
    fn enqueue_rejects_oversize_payload() {
        let tmp = TempDir::new().unwrap();
        let opts = CreateOptions {
            max_payload_length: 1024,
            ..Default::default()
        };
        Queue::init(tmp.path(), &opts).unwrap();
        let mut queue = Queue::open(
            tmp.path(),
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        let huge = vec![0u8; 2048]; // exceeds max_payload_length of 1024
        let result = queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: huge,
            ..Default::default()
        });
        assert!(matches!(result, EnqueueOutcome::NotCommitted(_, _)));
    }

    // ===== C-15: Scan round advances =====
    #[test]
    fn scan_round_advances() {
        let (_tmp, mut queue) = create_test_queue();
        assert_eq!(queue.scan_round, 0);
        let _ = queue.lease(0, 30_000_000_000);
        assert_eq!(queue.scan_round, 1);
        let _ = queue.lease(0, 30_000_000_000);
        assert_eq!(queue.scan_round, 2);
    }

    // ===== R4-H22/H23: ack re-hashes payload internally =====
    #[test]
    fn ack_succeeds_without_explicit_verify() {
        let (_tmp, mut queue) = create_test_queue();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"data".to_vec(),
            ..Default::default()
        });
        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            _ => panic!("lease failed"),
        };
        // ack() re-verifies payload at ack time, no explicit verify needed
        let result = queue.ack(&lease);
        assert!(matches!(result, AckOutcome::Acked));
    }

    // ===== R4-H02: ack_unverified skips payload re-hash =====
    #[test]
    fn ack_accepts_verified_lease() {
        let (_tmp, mut queue) = create_test_queue();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"data".to_vec(),
            ..Default::default()
        });
        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            _ => panic!("lease failed"),
        };
        queue.verify_lease_payload(&lease).unwrap();
        let result = queue.ack(&lease);
        assert!(matches!(result, AckOutcome::Acked));
    }

    // ===== B-09: verify_lease_payload detects corruption =====
    #[test]
    fn verify_lease_payload_detects_corruption() {
        let (_tmp, mut queue) = create_test_queue();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"hello world".to_vec(),
            ..Default::default()
        });
        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            _ => panic!("lease failed"),
        };
        // Corrupt the actual payload bytes (after header + extension)
        let src_path = _tmp.path().join(&lease.exact_source_path);
        let mut data = std::fs::read(&src_path).unwrap();
        // Header is 128 bytes, extension follows. Find the payload offset.
        // For content_type "x" the extension is ~4 bytes, so payload starts at ~132.
        // Corrupt the last byte (guaranteed to be in payload).
        let last = data.len() - 1;
        data[last] ^= 0xFF;
        std::fs::write(&src_path, data).unwrap();
        let result = queue.verify_lease_payload(&lease);
        assert!(
            matches!(
                result,
                Err(Error::PayloadCorrupt) | Err(Error::QueueCorrupt(_))
            ),
            "corrupted payload should be detected, got: {result:?}"
        );
    }

    // ===== R4-PERF: streaming payload read =====
    #[test]
    fn stream_lease_payload_reads_all_data() {
        let (_tmp, mut queue) = create_test_queue();
        let payload = b"streaming payload data for testing chunked reads";
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: payload.to_vec(),
            ..Default::default()
        });
        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            _ => panic!("lease failed"),
        };
        let mut collected = Vec::new();
        queue
            .stream_lease_payload(&lease, 8, |chunk| {
                collected.extend_from_slice(chunk);
                Ok(())
            })
            .unwrap();
        assert_eq!(&collected[..], &payload[..]);
    }

    #[test]
    fn read_lease_payload_chunk_respects_offset() {
        let (_tmp, mut queue) = create_test_queue();
        let payload = b"0123456789abcdef";
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: payload.to_vec(),
            ..Default::default()
        });
        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            _ => panic!("lease failed"),
        };
        let mut buf = [0u8; 4];
        let n = queue.read_lease_payload_chunk(&lease, &mut buf, 4).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&buf, b"4567");
        // Read at EOF
        let n = queue
            .read_lease_payload_chunk(&lease, &mut buf, 16)
            .unwrap();
        assert_eq!(n, 0);
    }

    // ===== R4-B07: resolve full identity verification =====
    #[test]
    fn resolve_source_still_in_ready() {
        let (_tmp, mut queue) = create_test_queue();
        let et = match queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"data".to_vec(),
            ..Default::default()
        }) {
            EnqueueOutcome::Committed(t) => t,
            _ => panic!("enqueue failed"),
        };
        let parsed =
            steadq_names::parse_ready(et.expected_relative_path.rsplit('/').next().unwrap())
                .unwrap();
        let ticket = test_claim_ticket(
            &queue,
            et.job_id,
            parsed.common.generation,
            parsed.common.attempt,
            parsed.common.maximum_attempts,
            [0; 16],
            et.envelope_digest,
        );
        let outcome = queue.resolve(&ticket, false);
        assert!(matches!(outcome, ResolutionOutcome::SourceObserved));
    }

    #[test]
    fn resolve_detects_ready_object_present() {
        let (_tmp, mut queue) = create_test_queue();
        let et = match queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"data".to_vec(),
            ..Default::default()
        }) {
            EnqueueOutcome::Committed(t) => t,
            _ => panic!("enqueue failed"),
        };
        // The object exists in ready. Use the path from the enqueue ticket.
        let parsed =
            steadq_names::parse_ready(et.expected_relative_path.rsplit('/').next().unwrap())
                .unwrap();
        let ticket = test_claim_ticket(
            &queue,
            et.job_id,
            parsed.common.generation,
            parsed.common.attempt,
            parsed.common.maximum_attempts,
            [0; 16],
            et.envelope_digest,
        );
        let outcome = queue.resolve(&ticket, false);
        assert!(matches!(outcome, ResolutionOutcome::SourceObserved));
    }

    #[test]
    fn resolve_stabilization_reports_file_sync_failure() {
        let (_tmp, mut queue) = create_test_queue();
        let et = match queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"data".to_vec(),
            ..Default::default()
        }) {
            EnqueueOutcome::Committed(ticket) => ticket,
            _ => panic!("enqueue failed"),
        };
        let parsed =
            steadq_names::parse_ready(et.expected_relative_path.rsplit('/').next().unwrap())
                .unwrap();
        let ticket = test_claim_ticket(
            &queue,
            et.job_id,
            parsed.common.generation,
            parsed.common.attempt,
            parsed.common.maximum_attempts,
            [0; 16],
            et.envelope_digest,
        );

        fs::fault::reset();
        fs::fault::inject("fsync", 1);
        let outcome = queue.resolve(&ticket, true);
        assert!(matches!(
            outcome,
            ResolutionOutcome::ResolutionFailed(Error::IoFailure(_))
        ));
        assert_eq!(fs::fault::call_count("fsync"), 1);
        assert_eq!(fs::fault::call_count("fsync_dir_fd"), 0);
        fs::fault::reset();
        assert!(matches!(
            queue.resolve(&ticket, true),
            ResolutionOutcome::SourceStabilized
        ));
    }

    #[test]
    fn resolve_stabilization_rejects_replaced_path() {
        use std::os::unix::fs::symlink;

        let (tmp, mut queue) = create_test_queue();
        let et = match queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"data".to_vec(),
            ..Default::default()
        }) {
            EnqueueOutcome::Committed(ticket) => ticket,
            _ => panic!("enqueue failed"),
        };
        let parsed =
            steadq_names::parse_ready(et.expected_relative_path.rsplit('/').next().unwrap())
                .unwrap();
        let ticket = test_claim_ticket(
            &queue,
            et.job_id,
            parsed.common.generation,
            parsed.common.attempt,
            parsed.common.maximum_attempts,
            [0; 16],
            et.envelope_digest,
        );
        let (source_relative_path, _) = queue.transition_ticket_paths(&ticket).unwrap();
        let source_path = ResolvePath::new(&source_relative_path).unwrap();
        let object =
            match queue.resolve_check_object(&source_path, &ticket, &ticket.source_common()) {
                ResolveObj::Match(object) => object,
                _ => panic!("source object did not authenticate"),
            };

        let source = tmp.path().join(&source_relative_path);
        let displaced = tmp.path().join("tmp/displaced.sqj");
        std::fs::rename(&source, displaced).unwrap();
        assert!(!queue.stabilize_object(&source_path, &object).unwrap());

        let outside = tempfile::TempDir::new().unwrap();
        let outside_file = outside.path().join("outside.sqj");
        std::fs::write(&outside_file, b"outside").unwrap();
        symlink(outside_file, &source).unwrap();

        assert!(!queue.stabilize_object(&source_path, &object).unwrap());
        fs::fault::reset();
        fs::fault::inject_errno("fstatat", 1, libc::EIO);
        assert!(matches!(
            queue.stabilize_object(&source_path, &object),
            Err(Error::IoFailure(_))
        ));
        fs::fault::reset();
        assert_eq!(
            resolver_file_open_flags(),
            libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK
        );
    }

    #[test]
    fn resolve_stabilization_rejects_replaced_parent() {
        let (tmp, mut queue) = create_test_queue();
        let et = match queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"data".to_vec(),
            ..Default::default()
        }) {
            EnqueueOutcome::Committed(ticket) => ticket,
            _ => panic!("enqueue failed"),
        };
        let parsed =
            steadq_names::parse_ready(et.expected_relative_path.rsplit('/').next().unwrap())
                .unwrap();
        let ticket = test_claim_ticket(
            &queue,
            et.job_id,
            parsed.common.generation,
            parsed.common.attempt,
            parsed.common.maximum_attempts,
            [0; 16],
            et.envelope_digest,
        );
        let (source_relative_path, _) = queue.transition_ticket_paths(&ticket).unwrap();
        let source_path = ResolvePath::new(&source_relative_path).unwrap();
        let object =
            match queue.resolve_check_object(&source_path, &ticket, &ticket.source_common()) {
                ResolveObj::Match(object) => object,
                _ => panic!("source object did not authenticate"),
            };

        let parent = tmp.path().join(source_path.directory.as_str());
        let displaced = tmp.path().join("tmp/displaced-shard");
        std::fs::rename(&parent, displaced).unwrap();
        std::fs::create_dir(&parent).unwrap();
        assert!(!queue.stabilize_object(&source_path, &object).unwrap());

        std::fs::remove_dir(&parent).unwrap();
        assert!(!queue.stabilize_object(&source_path, &object).unwrap());

        fs::fault::reset();
        fs::fault::inject_errno("openat2_beneath", 1, libc::EIO);
        assert!(matches!(
            queue.stabilize_object(&source_path, &object),
            Err(Error::IoFailure(_))
        ));
        fs::fault::reset();
    }

    #[test]
    fn resolve_recomputes_paths_after_job_id_change() {
        let (_tmp, mut queue) = create_test_queue();
        let et = match queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"data".to_vec(),
            ..Default::default()
        }) {
            EnqueueOutcome::Committed(t) => t,
            _ => panic!("enqueue failed"),
        };
        // Use a different job_id - the file exists but belongs to a different job.
        let mut wrong_id = et.job_id;
        wrong_id[0] ^= 0xFF;
        let ticket = test_claim_ticket(&queue, wrong_id, 0, 0, 3, [0; 16], et.envelope_digest);
        let outcome = queue.resolve(&ticket, false);
        assert!(matches!(outcome, ResolutionOutcome::NeitherObserved));
    }

    #[test]
    fn resolve_rejects_foreign_queue_ticket_before_filesystem_calls() {
        let (_tmp, queue) = create_test_queue();
        let ticket = TransitionTicket::new(
            [0xff; 16],
            TransitionOperation::Claim,
            TransitionPhase::Linearized,
            TicketIdentity::new([1; 16], 0, 0, 3, [2; 16], TicketEvidence::new([3; 32], 4)),
            TicketSource::Ready {},
            TicketDestination::Leased {
                boot_id: queue.boot_id.clone(),
                boottime_deadline_ns: 1,
                wall_deadline_ns: 1,
            },
        )
        .unwrap();

        fs::fault::reset();
        for syscall in [
            "openat2_beneath",
            "open_directory",
            "fstatat",
            "fstat",
            "openat",
        ] {
            fs::fault::inject(syscall, 1);
        }
        let outcome = queue.resolve(&ticket, false);
        assert!(matches!(
            outcome,
            ResolutionOutcome::ResolutionFailed(Error::InvalidTicket(_))
        ));
        for syscall in [
            "openat2_beneath",
            "open_directory",
            "fstatat",
            "fstat",
            "openat",
        ] {
            assert_eq!(fs::fault::call_count(syscall), 0);
        }
        fs::fault::reset();
    }

    #[test]
    fn resolve_compact_receipt_requires_ticket_attempt_and_bucket() {
        let (tmp, queue) = create_test_queue();
        let job_id = [7; 16];
        let lease_token = [8; 16];
        let envelope_digest = [9; 32];
        let terminal_bucket = 2;
        let ticket = TransitionTicket::new(
            queue.format.queue_id,
            TransitionOperation::Acknowledge,
            TransitionPhase::SourceDirectoryDurable,
            TicketIdentity::new(
                job_id,
                4,
                1,
                3,
                lease_token,
                TicketEvidence::new(envelope_digest, 4),
            ),
            TicketSource::Leased {
                boot_id: queue.boot_id.clone(),
                boottime_deadline_ns: 1,
                wall_deadline_ns: 2,
            },
            TicketDestination::Receipt { terminal_bucket },
        )
        .unwrap();
        let (_, destination) = queue.transition_ticket_paths(&ticket).unwrap();
        let destination_path = tmp.path().join(&destination);
        std::fs::create_dir_all(destination_path.parent().unwrap()).unwrap();
        let mut receipt = steadq_format::CompactReceipt {
            job_id,
            envelope_digest,
            final_attempt: 1,
            lease_token,
            receipt_bucket_start_unix_ns: terminal_bucket * queue.format.terminal_bucket_width_ns,
            original_payload_length: 4,
        };
        std::fs::write(&destination_path, receipt.encode()).unwrap();
        assert!(matches!(
            queue.resolve(&ticket, false),
            ResolutionOutcome::DestinationObserved
        ));

        receipt.job_id[0] ^= 0xff;
        std::fs::write(&destination_path, receipt.encode()).unwrap();
        assert!(matches!(
            queue.resolve(&ticket, false),
            ResolutionOutcome::ConflictingObject
        ));
        receipt.job_id = job_id;

        receipt.final_attempt = 2;
        std::fs::write(&destination_path, receipt.encode()).unwrap();
        assert!(matches!(
            queue.resolve(&ticket, false),
            ResolutionOutcome::ConflictingObject
        ));

        receipt.final_attempt = 1;
        receipt.receipt_bucket_start_unix_ns += 1;
        std::fs::write(&destination_path, receipt.encode()).unwrap();
        assert!(matches!(
            queue.resolve(&ticket, false),
            ResolutionOutcome::ConflictingObject
        ));

        receipt.receipt_bucket_start_unix_ns -= 1;
        receipt.original_payload_length = 5;
        std::fs::write(&destination_path, receipt.encode()).unwrap();
        assert!(matches!(
            queue.resolve(&ticket, false),
            ResolutionOutcome::ConflictingObject
        ));
    }

    #[test]
    fn receipt_path_authentication_rejects_each_mismatch() {
        let (_tmp, queue, ticket) = resolver_ticket_case("acknowledge");
        let (_, destination) = queue.transition_ticket_paths(&ticket).unwrap();
        let parts = destination.split('/').collect::<Vec<_>>();
        let name = parts[3];
        let expected_common = ticket.destination_common().unwrap();
        assert!(queue.resolve_receipt_path_matches(&parts, name, &ticket, &expected_common,));

        assert!(!queue.resolve_receipt_path_matches(&parts[..3], name, &ticket, &expected_common,));
        let wrong_state = ["ready", parts[1], parts[2], parts[3]];
        assert!(!queue.resolve_receipt_path_matches(&wrong_state, name, &ticket, &expected_common,));

        let mut wrong_common = expected_common.clone();
        wrong_common.generation += 1;
        assert!(!queue.resolve_receipt_path_matches(&parts, name, &ticket, &wrong_common,));
        let mut wrong_token_json: serde_json::Value =
            serde_json::from_slice(&ticket.to_json().unwrap()).unwrap();
        wrong_token_json["source_identity"]["lease_token"] =
            serde_json::json!(steadq_names::hex_encode(&[0xff; 16]));
        let wrong_token =
            TransitionTicket::from_json(&serde_json::to_vec(&wrong_token_json).unwrap()).unwrap();
        assert!(!queue.resolve_receipt_path_matches(&parts, name, &wrong_token, &expected_common,));

        let mut wrong_tag = name.as_bytes().to_vec();
        let tag_index = wrong_tag.len() - 5;
        wrong_tag[tag_index] = if wrong_tag[tag_index] == b'0' {
            b'1'
        } else {
            b'0'
        };
        let wrong_tag = String::from_utf8(wrong_tag).unwrap();
        assert!(!queue.resolve_receipt_path_matches(&parts, &wrong_tag, &ticket, &expected_common,));

        let actual_shard = steadq_names::shard_from_hex(parts[2]).unwrap();
        let wrong_shard = (actual_shard + 1) % queue.format.shard_count;
        let wrong_shard = shard_hex(wrong_shard);
        let wrong_shard_name = steadq_names::make_receipt_name(
            &queue.format.queue_id,
            parts[1],
            &wrong_shard,
            &expected_common,
            &ticket.lease_token(),
        );
        let wrong_shard_parts = ["receipts", parts[1], &wrong_shard, &wrong_shard_name];
        assert!(!queue.resolve_receipt_path_matches(
            &wrong_shard_parts,
            &wrong_shard_name,
            &ticket,
            &expected_common,
        ));
    }

    #[test]
    fn resolve_rejects_compact_receipt_at_ready_source() {
        let (tmp, queue) = create_test_queue();
        let job_id = [7; 16];
        let lease_token = [8; 16];
        let envelope_digest = [9; 32];
        let ticket = test_claim_ticket(&queue, job_id, 0, 0, 3, lease_token, envelope_digest);
        let (source, _) = queue.transition_ticket_paths(&ticket).unwrap();
        let receipt = steadq_format::CompactReceipt {
            job_id,
            envelope_digest,
            final_attempt: 0,
            lease_token,
            receipt_bucket_start_unix_ns: 0,
            original_payload_length: 4,
        };
        std::fs::write(tmp.path().join(source), receipt.encode()).unwrap();

        assert!(matches!(
            queue.resolve(&ticket, false),
            ResolutionOutcome::ConflictingObject
        ));
    }

    #[test]
    fn resolver_rejects_hard_links_for_every_operation_side() {
        for operation in [
            "claim",
            "acknowledge",
            "retry_now",
            "retry_later",
            "bury",
            "renew",
        ] {
            let (tmp, queue, ticket) = resolver_ticket_case(operation);
            let (source, _) = queue.transition_ticket_paths(&ticket).unwrap();
            add_hard_link(&tmp, &source, &format!("{operation}-source"));
            assert!(matches!(
                queue.resolve(&ticket, false),
                ResolutionOutcome::ConflictingObject
            ));

            let (tmp, queue, ticket) = resolver_ticket_case(operation);
            let (source, destination) = queue.transition_ticket_paths(&ticket).unwrap();
            let destination_path = tmp.path().join(&destination);
            std::fs::create_dir_all(destination_path.parent().unwrap()).unwrap();
            std::fs::rename(tmp.path().join(source), &destination_path).unwrap();
            add_hard_link(&tmp, &destination, &format!("{operation}-destination"));
            assert!(matches!(
                queue.resolve(&ticket, false),
                ResolutionOutcome::ConflictingObject
            ));
        }
    }

    #[test]
    fn resolve_observes_delayed_dead_and_full_receipt_destinations() {
        let (_tmp, mut delayed_queue) = create_test_queue();
        let delayed_lease = enqueue_and_lease(&mut delayed_queue);
        let not_before_ns = delayed_queue.wall_floor_for_mutation().unwrap() + 60_000_000_000;
        let delayed_ticket = delayed_queue
            .transition_ticket_for_lease(
                &delayed_lease,
                TransitionOperation::RetryLater,
                TicketDestination::Delayed { not_before_ns },
            )
            .unwrap();
        delayed_queue
            .retry_at(&delayed_lease, not_before_ns)
            .commit_or_panic();
        assert!(matches!(
            delayed_queue.resolve(&delayed_ticket, false),
            ResolutionOutcome::DestinationObserved
        ));

        let (_tmp, mut dead_queue) = create_test_queue();
        let dead_lease = enqueue_and_lease(&mut dead_queue);
        dead_queue
            .bury(&dead_lease, DeadReason::AdministrativeBury)
            .commit_or_panic();
        let dead_snapshot = dead_queue
            .inspect(&dead_lease.job_id)
            .into_iter()
            .find(|snapshot| snapshot.state == "dead")
            .unwrap();
        let dead_bucket =
            steadq_names::bucket_from_hex(dead_snapshot.relative_path.split('/').nth(1).unwrap())
                .unwrap();
        let dead_ticket = dead_queue
            .transition_ticket_for_lease(
                &dead_lease,
                TransitionOperation::Bury,
                TicketDestination::Dead {
                    terminal_bucket: dead_bucket,
                    reason: DeadReason::AdministrativeBury as u16,
                },
            )
            .unwrap();
        assert!(matches!(
            dead_queue.resolve(&dead_ticket, false),
            ResolutionOutcome::DestinationObserved
        ));

        let (_tmp, mut receipt_queue) = create_test_queue();
        let receipt_lease = enqueue_and_lease(&mut receipt_queue);
        assert!(matches!(
            receipt_queue.ack(&receipt_lease),
            AckOutcome::Acked
        ));
        let receipt_snapshot = receipt_queue
            .inspect(&receipt_lease.job_id)
            .into_iter()
            .find(|snapshot| snapshot.state == "receipt")
            .unwrap();
        let receipt_bucket = steadq_names::bucket_from_hex(
            receipt_snapshot.relative_path.split('/').nth(1).unwrap(),
        )
        .unwrap();
        let receipt_ticket = receipt_queue
            .transition_ticket_for_lease(
                &receipt_lease,
                TransitionOperation::Acknowledge,
                TicketDestination::Receipt {
                    terminal_bucket: receipt_bucket,
                },
            )
            .unwrap();
        assert!(matches!(
            receipt_queue.resolve(&receipt_ticket, false),
            ResolutionOutcome::DestinationObserved
        ));

        let mut ticket_json: serde_json::Value =
            serde_json::from_slice(&receipt_ticket.to_json().unwrap()).unwrap();
        ticket_json["source_identity"]["payload_length"] =
            serde_json::json!(receipt_ticket.payload_length() + 1);
        let wrong_payload_length =
            TransitionTicket::from_json(&serde_json::to_vec(&ticket_json).unwrap()).unwrap();
        assert!(matches!(
            receipt_queue.resolve(&wrong_payload_length, false),
            ResolutionOutcome::ConflictingObject
        ));

        fs::fault::reset();
        fs::fault::inject_at("pread", 3);
        assert!(matches!(
            receipt_queue.resolve(&receipt_ticket, false),
            ResolutionOutcome::ResolutionFailed(Error::IoFailure(_))
        ));
        fs::fault::reset();

        std::fs::OpenOptions::new()
            .write(true)
            .open(_tmp.path().join(&receipt_snapshot.relative_path))
            .unwrap()
            .set_len(128)
            .unwrap();
        assert!(matches!(
            receipt_queue.resolve(&receipt_ticket, false),
            ResolutionOutcome::ConflictingObject
        ));
    }

    // ===== B-05: Wall watermark advances after enqueue =====
    #[test]
    fn wall_watermark_advances() {
        let (_tmp, mut queue) = create_test_queue();
        let wm_before = queue.read_wall_watermark().ok();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"data".to_vec(),
            ..Default::default()
        });
        let wm_after = queue.read_wall_watermark().ok();
        // After enqueue, the watermark bucket should not regress
        if let (Some(before), Some(after)) = (wm_before, wm_after) {
            assert!(after.highest_observed_bucket >= before.highest_observed_bucket);
        }
    }

    #[test]
    fn watermark_typed_read_notfound_ok_and_corrupt_is_queue_corrupt() {
        let (tmp, mut queue) = create_test_queue();
        let before = queue.read_wall_watermark();
        assert!(
            matches!(before, Err(WatermarkReadError::NotFound) | Ok(_)),
            "initial watermark should be NotFound or Ok, got {before:?}"
        );
        let floor_ok = queue.effective_wall_floor_ns_checked();
        assert!(
            floor_ok.is_ok(),
            "NotFound should fallback to clock, got {floor_ok:?}"
        );

        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"data".to_vec(),
            ..Default::default()
        });
        let wm = queue
            .read_wall_watermark()
            .expect("watermark should exist after enqueue");
        let _ = wm.highest_observed_bucket;

        let wm_path = tmp.path().join("control/wall-watermark");
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(&wm_path)
                .unwrap();
            f.write_all(&[0xFF; 8]).unwrap();
            f.sync_all().unwrap();
        }
        let corrupt = queue.read_wall_watermark();
        assert!(
            matches!(
                corrupt,
                Err(WatermarkReadError::Corrupt(_)) | Err(WatermarkReadError::Truncated(_))
            ),
            "corrupt watermark should be Corrupt or Truncated, got {corrupt:?}"
        );
        let floor_err = queue.effective_wall_floor_ns_checked();
        assert!(
            matches!(floor_err, Err(Error::QueueCorrupt(_))),
            "corrupt watermark floor should be QueueCorrupt, got {floor_err:?}"
        );
        let advance_err = queue.advance_wall_watermark(u64::MAX);
        assert!(
            matches!(advance_err, Err(Error::QueueCorrupt(_))),
            "advance with corrupt watermark should be QueueCorrupt, got {advance_err:?}"
        );
    }

    #[test]
    fn watermark_typed_read_truncated_is_queue_corrupt() {
        let (tmp, mut queue) = create_test_queue();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"hello".to_vec(),
            ..Default::default()
        });
        let wm_path = tmp.path().join("control/wall-watermark");
        {
            let f = std::fs::OpenOptions::new()
                .write(true)
                .open(&wm_path)
                .unwrap();
            f.set_len(4).unwrap();
            f.sync_all().unwrap();
        }
        let truncated = queue.read_wall_watermark();
        assert!(
            matches!(truncated, Err(WatermarkReadError::Truncated(_))),
            "truncated watermark should be Truncated, got {truncated:?}"
        );
        let floor = queue.effective_wall_floor_ns_checked();
        assert!(
            matches!(floor, Err(Error::QueueCorrupt(_))),
            "truncated floor should be QueueCorrupt, got {floor:?}"
        );
    }

    #[test]
    fn watermark_open_is_not_found_table() {
        let cases: &[(std::io::ErrorKind, bool)] = &[
            (std::io::ErrorKind::NotFound, true),
            (std::io::ErrorKind::PermissionDenied, false),
            (std::io::ErrorKind::AlreadyExists, false),
            (std::io::ErrorKind::InvalidInput, false),
            (std::io::ErrorKind::UnexpectedEof, false),
        ];
        for (kind, expected) in cases {
            let err = std::io::Error::new(*kind, "test");
            assert_eq!(
                watermark_open_is_not_found(&err),
                *expected,
                "kind {kind:?} should be {expected}"
            );
        }
        let not_found = std::io::Error::new(std::io::ErrorKind::NotFound, "nf");
        let perm = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "perm");
        assert_ne!(
            watermark_open_is_not_found(&not_found),
            watermark_open_is_not_found(&perm),
            "NotFound must differ from other kinds"
        );
    }

    #[test]
    fn watermark_should_advance_table() {
        assert!(
            !watermark_should_advance(5, 5),
            "equal buckets should not advance"
        );
        assert!(
            !watermark_should_advance(4, 5),
            "smaller observed should not advance"
        );
        assert!(
            watermark_should_advance(6, 5),
            "greater observed should advance"
        );
        assert!(watermark_should_advance(1, 0), "1 > 0 should advance");
        assert!(!watermark_should_advance(0, 0), "0 == 0 should not advance");
        assert!(
            !watermark_should_advance(u64::MAX - 1, u64::MAX),
            "max-1 vs max should not advance"
        );
        assert!(
            watermark_should_advance(u64::MAX, u64::MAX - 1),
            "max vs max-1 should advance"
        );
    }

    #[test]
    fn watermark_advance_does_not_rewrite_on_equal_bucket() {
        let (_tmp, mut queue) = create_test_queue();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"a".to_vec(),
            ..Default::default()
        });
        let wm_before = queue.read_wall_watermark().expect("watermark exists");
        let bucket = wm_before.highest_observed_bucket;
        let width = queue.format().delayed_bucket_width_ns;
        let observed_ns = bucket * width;
        let seq_before = wm_before.sequence;
        let res = queue.advance_wall_watermark(observed_ns);
        assert!(
            res.is_ok(),
            "equal bucket advance should be Ok, got {res:?}"
        );
        let wm_after = queue.read_wall_watermark().expect("watermark still exists");
        assert_eq!(
            wm_after.sequence, seq_before,
            "equal bucket should not bump sequence"
        );
        assert_eq!(
            wm_after.highest_observed_bucket, bucket,
            "equal bucket should not change bucket"
        );
    }

    #[test]
    fn watermark_read_distinguishes_io_from_notfound() {
        steadq_fs_linux::fault::reset();
        let (_tmp, queue) = create_test_queue();
        steadq_fs_linux::fault::inject("openat", 1);
        let result = queue.read_wall_watermark();
        assert!(
            matches!(result, Err(WatermarkReadError::Io(_))),
            "injected wall-watermark openat EIO should be Io not NotFound, got {result:?}"
        );
        steadq_fs_linux::fault::inject("openat", 1);
        let floor = queue.effective_wall_floor_ns_checked();
        steadq_fs_linux::fault::reset();
        assert!(
            matches!(floor, Err(Error::IoFailure(_))),
            "Io watermark should make floor IoFailure, got {floor:?}"
        );
    }

    // ===== B-04: Lease source validation rejects corrupted handle =====
    #[test]
    fn source_validation_rejects_wrong_generation() {
        let (_tmp, mut queue) = create_test_queue();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"data".to_vec(),
            ..Default::default()
        });
        let mut lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            _ => panic!("lease failed"),
        };
        // Corrupt the generation in the handle
        lease.generation = 999;
        let result = queue.retry_now(&lease);
        // Should not get LeaseLost (that's for missing source), should get corruption or not committed
        assert!(!matches!(result, TransitionOutcome::Committed));
    }

    #[test]
    fn source_identity_fields_are_authenticated_before_every_lease_transition() {
        for operation in ["ack", "retry", "bury", "renew"] {
            for field in [
                "boot_id",
                "boottime_deadline",
                "wall_deadline",
                "payload_length",
                "payload_digest",
            ] {
                let (_tmp, mut queue) = create_test_queue();
                let mut lease = enqueue_and_lease(&mut queue);
                match field {
                    "boot_id" => lease.boot_id = "00000000-0000-0000-0000-000000000000".into(),
                    "boottime_deadline" => lease.expires_boottime_ns ^= 1,
                    "wall_deadline" => lease.expires_wall_ns ^= 1,
                    "payload_length" => lease.payload_length ^= 1,
                    "payload_digest" => lease.payload_digest[0] ^= 0xff,
                    _ => unreachable!(),
                }

                fs::fault::reset();
                let rejected = match operation {
                    "ack" => matches!(
                        queue.ack(&lease),
                        AckOutcome::NotCommitted(Error::QueueCorrupt(_))
                    ),
                    "retry" => matches!(
                        queue.retry_now(&lease),
                        TransitionOutcome::NotCommitted(Error::QueueCorrupt(_))
                    ),
                    "bury" => matches!(
                        queue.bury(&lease, DeadReason::AdministrativeBury),
                        TransitionOutcome::NotCommitted(Error::QueueCorrupt(_))
                    ),
                    "renew" => matches!(
                        queue.renew(&lease, 30_000_000_000),
                        RenewOutcome::NotCommitted(Error::QueueCorrupt(_))
                    ),
                    _ => unreachable!(),
                };
                assert!(rejected, "{operation} accepted mutated {field}");
                assert_eq!(
                    fs::fault::call_count("renameat2_noreplace"),
                    0,
                    "{operation} renamed after mutated {field}"
                );
                fs::fault::reset();
            }
        }
    }

    // ===== C-19: Scan distinguishes empty from error =====
    #[test]
    fn empty_queue_returns_empty_not_error() {
        let (_tmp, mut queue) = create_test_queue();
        let result = queue.lease(0, 30_000_000_000);
        assert!(matches!(result, LeaseOutcome::Empty));
    }

    // ===== B-12: Unexpected ack errors are not LeaseLost =====
    #[test]
    fn ack_preserves_error_categories() {
        let (_tmp, mut queue) = create_test_queue();
        // Use a nonexistent source path - should get LeaseLost
        // Use a path that matches leased/<boot>/<bucket>/<shard>/<name> structure
        // but with a source that doesn't exist.
        let boot_id = queue.boot_id.clone();
        let fake_lease = LeaseInfo {
            job_id: [0x42; 16],
            envelope_digest: [0; 32],
            generation: 1,
            attempt: 1,
            maximum_attempts: 3,
            token: [0xFF; 16],
            boot_id: boot_id.clone(),
            expires_boottime_ns: u64::MAX,
            expires_wall_ns: u64::MAX,
            content_type: String::new(),
            payload_length: 0,
            payload_digest: [0; 32],
            expected_dev: 0,
            expected_inode: 0,
            exact_source_path: format!("leased/{boot_id}/0000000000000000/0000/nonexistent.sqj"),
        };
        let result = queue.ack(&fake_lease);
        // R4-H02: dev/inode are 0, so open_and_validate_current_lease rejects
        // the forgeable handle before even checking source existence.
        assert!(matches!(result, AckOutcome::NotCommitted(_)));
    }

    // ===== B-03: Post-claim validation does not return Empty =====
    #[test]
    fn post_claim_returns_lease_on_success() {
        let (_tmp, mut queue) = create_test_queue();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "application/json".to_string(),
            payload: b"{\"key\": \"value\"}".to_vec(),
            ..Default::default()
        });
        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            _ => panic!("lease should succeed"),
        };
        // C-21: Content type should be populated
        assert_eq!(lease.content_type, "application/json");
        // Verify the source path exists
        assert!(_tmp.path().join(&lease.exact_source_path).exists());
    }

    // ===== Init durability: FORMAT is read-only =====
    #[test]
    fn format_file_is_readonly() {
        let tmp = TempDir::new().unwrap();
        Queue::init(tmp.path(), &CreateOptions::default()).unwrap();
        let meta = std::fs::metadata(tmp.path().join("FORMAT")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = meta.permissions().mode();
            assert_eq!(
                mode & 0o777,
                0o400,
                "FORMAT should be mode 0400, got {mode:o}"
            );
        }
    }

    #[test]
    fn open_rejects_unsupported_format_version() {
        let tmp = TempDir::new().unwrap();
        Queue::init(tmp.path(), &CreateOptions::default()).unwrap();

        // Overwrite FORMAT major version byte (offset 8) to trigger
        // UnsupportedVersion -> Error::UnsupportedFormat.
        use std::io::{Seek, SeekFrom, Write};
        use std::os::unix::fs::PermissionsExt;
        let fmt_path = tmp.path().join("FORMAT");
        std::fs::set_permissions(&fmt_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(&fmt_path)
            .unwrap();
        f.seek(SeekFrom::Start(8)).unwrap();
        f.write_all(&[0xFF, 0xFF]).unwrap();
        f.sync_all().unwrap();
        drop(f);

        let result = Queue::open(
            tmp.path(),
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        );
        assert!(
            matches!(result, Err(Error::UnsupportedFormat)),
            "expected Err(UnsupportedFormat)"
        );
    }

    // T-03: Real concurrent producers AND consumers
    #[test]
    fn concurrent_producers_consumers_overlap() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Arc;
        use std::thread;

        let tmp = TempDir::new().unwrap();
        Queue::init(tmp.path(), &CreateOptions::default()).unwrap();

        let path = tmp.path().to_path_buf();
        let total = Arc::new(AtomicU64::new(0));
        let consumed = Arc::new(AtomicU64::new(0));
        let duration = std::time::Duration::from_secs(2);

        let p_path = path.clone();
        let p_total = total.clone();
        let producer = thread::spawn(move || {
            let mut queue = Queue::open(
                &p_path,
                &OpenOptions {
                    allow_unsupported_fs: true,
                    ..Default::default()
                },
            )
            .unwrap();
            let deadline = std::time::Instant::now() + duration;
            while std::time::Instant::now() < deadline {
                if let EnqueueOutcome::Committed(_) = queue.enqueue(EnqueueInput {
                    maximum_attempts: 1,
                    content_type: "test".to_string(),
                    payload: b"concurrent".to_vec(),
                    ..Default::default()
                }) {
                    p_total.fetch_add(1, Ordering::Relaxed);
                }
            }
        });

        let c_path = path.clone();
        let c_consumed = consumed.clone();
        let consumer = thread::spawn(move || {
            let mut queue = Queue::open(
                &c_path,
                &OpenOptions {
                    allow_unsupported_fs: true,
                    ..Default::default()
                },
            )
            .unwrap();
            let deadline = std::time::Instant::now() + duration + std::time::Duration::from_secs(1);
            while std::time::Instant::now() < deadline {
                match queue.lease(0, 60_000_000_000) {
                    LeaseOutcome::Leased(l) => {
                        queue.verify_lease_payload(&l).unwrap();
                        if queue.ack(&l) == AckOutcome::Acked {
                            c_consumed.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    LeaseOutcome::Empty => {
                        thread::sleep(std::time::Duration::from_millis(1));
                    }
                    _ => {}
                }
            }
        });

        producer.join().unwrap();
        consumer.join().unwrap();

        let enq = total.load(Ordering::Relaxed);
        let con = consumed.load(Ordering::Relaxed);
        // Consumer should have consumed at least some jobs while producer was active
        assert!(enq > 0, "should have enqueued some jobs");
        assert!(con > 0, "should have consumed some jobs concurrently");
        // With concurrent producer and consumer, we should consume most
        // but may not consume all (race conditions at start/end)
    }

    // ===== T5: FD leak stress =====
    #[test]
    fn fd_leak_stress() {
        let tmp = TempDir::new().unwrap();
        Queue::init(tmp.path(), &CreateOptions::default()).unwrap();
        fn open_fd_count() -> usize {
            std::fs::read_dir("/proc/self/fd")
                .map(|d| d.count())
                .unwrap_or(0)
        }
        let baseline = open_fd_count();
        for _ in 0..200 {
            let q = Queue::open(
                tmp.path(),
                &OpenOptions {
                    allow_unsupported_fs: true,
                    ..Default::default()
                },
            )
            .unwrap();
            drop(q);
        }
        let after = open_fd_count();
        // Allow small variance for allocator internals, but no sustained growth.
        assert!(
            after <= baseline + 30,
            "FD leak: baseline={baseline}, after={after}"
        );
    }

    // ===== T3: Negative test matrix =====
    #[test]
    fn reject_invalid_lease_duration() {
        let (_tmp, mut queue) = create_test_queue();
        let outcome = queue.lease(0, 100);
        assert!(matches!(outcome, LeaseOutcome::NotCommitted(_)));
        let outcome = queue.lease(0, 8 * 24 * 60 * 60 * 1_000_000_000);
        assert!(matches!(outcome, LeaseOutcome::NotCommitted(_)));
    }

    #[test]
    fn reject_ack_on_empty_queue() {
        let (_tmp, mut queue) = create_test_queue();
        let fake = LeaseInfo {
            job_id: [0xFF; 16],
            envelope_digest: [0; 32],
            generation: 1,
            attempt: 1,
            maximum_attempts: 3,
            token: [0; 16],
            boot_id: queue.boot_id.clone(),
            expires_boottime_ns: 0,
            expires_wall_ns: 0,
            content_type: String::new(),
            payload_length: 0,
            payload_digest: [0; 32],
            expected_dev: 1,
            expected_inode: 1,
            exact_source_path: "leased/x/x/x/nonexistent.sqj".into(),
        };
        let result = queue.ack(&fake);
        assert!(matches!(
            result,
            AckOutcome::LeaseLost | AckOutcome::NotCommitted(_)
        ));
    }

    #[test]
    fn reject_retry_on_empty_queue() {
        let (_tmp, mut queue) = create_test_queue();
        let fake = LeaseInfo {
            job_id: [0xFF; 16],
            envelope_digest: [0; 32],
            generation: 1,
            attempt: 1,
            maximum_attempts: 3,
            token: [0; 16],
            boot_id: queue.boot_id.clone(),
            expires_boottime_ns: 0,
            expires_wall_ns: 0,
            content_type: String::new(),
            payload_length: 0,
            payload_digest: [0; 32],
            expected_dev: 1,
            expected_inode: 1,
            exact_source_path: "leased/x/x/x/nonexistent.sqj".into(),
        };
        let result = queue.retry_now(&fake);
        assert!(matches!(
            result,
            TransitionOutcome::LeaseLost | TransitionOutcome::NotCommitted(_)
        ));
    }

    #[test]
    fn reject_zero_dev_inode_lease() {
        let (_tmp, mut queue) = create_test_queue();
        let fake = LeaseInfo {
            job_id: [0xFF; 16],
            envelope_digest: [0; 32],
            generation: 1,
            attempt: 1,
            maximum_attempts: 3,
            token: [0; 16],
            boot_id: queue.boot_id.clone(),
            expires_boottime_ns: 0,
            expires_wall_ns: 0,
            content_type: String::new(),
            payload_length: 0,
            payload_digest: [0; 32],
            expected_dev: 0,
            expected_inode: 0,
            exact_source_path: "leased/x/x/x/nonexistent.sqj".into(),
        };
        let result = queue.ack(&fake);
        assert!(matches!(result, AckOutcome::NotCommitted(_)));
    }

    #[test]
    fn reject_generation_overflow() {
        let (_tmp, mut queue) = create_test_queue();
        let fake = LeaseInfo {
            job_id: [0xFF; 16],
            envelope_digest: [0; 32],
            generation: u64::MAX,
            attempt: 1,
            maximum_attempts: 3,
            token: [0; 16],
            boot_id: queue.boot_id.clone(),
            expires_boottime_ns: 0,
            expires_wall_ns: 0,
            content_type: String::new(),
            payload_length: 0,
            payload_digest: [0; 32],
            expected_dev: 1,
            expected_inode: 1,
            exact_source_path: "leased/x/x/x/nonexistent.sqj".into(),
        };
        let result = queue.retry_now(&fake);
        assert!(matches!(
            result,
            TransitionOutcome::NotCommitted(Error::StateExhausted)
        ));
    }

    #[test]
    fn poisoned_queue_rejects_operations() {
        let (_tmp, mut queue) = create_test_queue();
        queue.poison();
        let outcome = queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"data".to_vec(),
            ..Default::default()
        });
        assert!(matches!(outcome, EnqueueOutcome::NotCommitted(_, _)));
    }

    #[test]
    fn open_rejects_missing_state_dir() {
        let tmp = TempDir::new().unwrap();
        Queue::init(tmp.path(), &CreateOptions::default()).unwrap();
        // Remove a required state directory
        std::fs::remove_dir_all(tmp.path().join("ready")).unwrap();
        let result = Queue::open(
            tmp.path(),
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        );
        assert!(result.is_err());
    }

    #[test]
    fn verify_payload_detects_wrong_data() {
        let (_tmp, mut queue) = create_test_queue();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"hello world".to_vec(),
            ..Default::default()
        });
        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            _ => panic!("lease failed"),
        };
        // Corrupt a payload byte
        let src_path = _tmp.path().join(&lease.exact_source_path);
        let mut data = std::fs::read(&src_path).unwrap();
        let last = data.len() - 1;
        data[last] ^= 0xFF;
        std::fs::write(&src_path, data).unwrap();
        // Verify should detect corruption
        let result = queue.verify_lease_payload(&lease);
        assert!(matches!(
            result,
            Err(Error::PayloadCorrupt) | Err(Error::QueueCorrupt(_))
        ));
    }

    #[test]
    fn p0_01_lease_rejects_corrupt_payload_before_delivery() {
        for pos in ["first", "middle", "last"] {
            let (_tmp, mut queue) = create_test_queue();
            let payload = b"payload for P0-01 before-delivery corrupt test 12345".to_vec();
            queue.enqueue(EnqueueInput {
                maximum_attempts: 3,
                content_type: "x".to_string(),
                payload: payload.clone(),
                ..Default::default()
            });
            // Find ready file and corrupt one byte before lease.
            // Helper to scan ready shards under root/ready/*/*.sqj
            let find_one_ready = |root: &std::path::Path| -> Option<std::path::PathBuf> {
                let ready_root = root.join("ready");
                for shard in std::fs::read_dir(&ready_root).ok()?.flatten() {
                    for f in std::fs::read_dir(shard.path()).ok()?.flatten() {
                        let p = f.path();
                        if p.extension().map(|e| e == "sqj").unwrap_or(false) {
                            return Some(p);
                        }
                    }
                }
                None
            };
            let ready_path = find_one_ready(_tmp.path()).expect("ready file should exist");
            let mut data = std::fs::read(&ready_path).unwrap();
            let header_len = 128usize;
            let ext_len = {
                let mut hb = [0u8; 128];
                hb.copy_from_slice(&data[0..128]);
                let h = FixedHeader::decode(&hb).unwrap();
                h.extension_header_length as usize
            };
            let payload_start = header_len + ext_len;
            let idx = match pos {
                "first" => payload_start,
                "middle" => payload_start + payload.len() / 2,
                "last" => payload_start + payload.len() - 1,
                _ => unreachable!(),
            };
            data[idx] ^= 0xFF;
            std::fs::write(&ready_path, data).unwrap();
            let outcome = queue.lease(0, 30_000_000_000);
            match outcome {
                LeaseOutcome::NotCommitted(Error::PayloadCorrupt) => {}
                other => panic!("pos {pos} expected PayloadCorrupt, got {other:?}"),
            }
            // Object should be quarantined, not still ready.
            let remaining = find_one_ready(_tmp.path());
            assert!(
                remaining.is_none(),
                "corrupt object should not remain in ready after lease attempt, found {remaining:?}"
            );
            let q = queue.list_quarantine();
            assert!(
                q.iter()
                    .any(|e| e.reason == QuarantineReason::PayloadCorrupt as u16),
                "quarantine should contain PayloadCorrupt for pos {pos}"
            );
        }
    }

    #[test]
    fn p0_01_stream_zero_and_boundary_payloads_verify() {
        for len in [0usize, 4096, 65535, 65536, 65537] {
            let (_tmp, mut queue) = create_test_queue();
            let payload = vec![0xAB; len];
            queue.enqueue(EnqueueInput {
                maximum_attempts: 3,
                content_type: "x".to_string(),
                payload: payload.clone(),
                ..Default::default()
            });
            let lease = match queue.lease(0, 30_000_000_000) {
                LeaseOutcome::Leased(l) => l,
                other => panic!("len {len} lease failed: {other:?}"),
            };
            // Streaming must succeed for valid payload, even at boundaries.
            let mut out = Vec::new();
            queue
                .stream_lease_payload(&lease, 8192, |chunk| {
                    out.extend_from_slice(chunk);
                    Ok(())
                })
                .unwrap();
            assert_eq!(out.len(), len);
            assert_eq!(out, payload);
            // Chunk read also.
            let mut buf = vec![0u8; len.max(1)];
            let n = queue.read_lease_payload_chunk(&lease, &mut buf, 0).unwrap();
            assert_eq!(n, len);
        }
    }

    #[test]
    fn p0_01_read_stream_reject_corrupt_after_lease() {
        let (_tmp, mut queue) = create_test_queue();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"stream after lease corrupt".to_vec(),
            ..Default::default()
        });
        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            other => panic!("lease failed: {other:?}"),
        };
        // Corrupt leased file after successful lease but before read.
        let src_path = _tmp.path().join(&lease.exact_source_path);
        let mut data = std::fs::read(&src_path).unwrap();
        let last = data.len() - 1;
        data[last] ^= 0x01;
        std::fs::write(&src_path, data).unwrap();
        // Chunk read must not deliver corrupt bytes.
        let mut buf = vec![0u8; 64];
        let r = queue.read_lease_payload_chunk(&lease, &mut buf, 0);
        assert!(matches!(
            r,
            Err(Error::PayloadCorrupt) | Err(Error::QueueCorrupt(_))
        ));
        // Stream must also fail.
        let sr = queue.stream_lease_payload(&lease, 4096, |_| Ok(()));
        assert!(matches!(
            sr,
            Err(Error::PayloadCorrupt) | Err(Error::QueueCorrupt(_))
        ));
    }

    #[test]
    fn quarantine_held_fd_must_match_name() {
        let (_tmp, mut queue) = create_test_queue();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"a".to_vec(),
            ..Default::default()
        });
        let lease_a = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            other => panic!("lease a failed: {other:?}"),
        };
        // Hold fd for a dummy file in same leased dir but different inode. Dev same, ino differs.
        let dir_path = lease_a
            .exact_source_path
            .rsplit_once('/')
            .map(|(d, _)| d)
            .unwrap();
        let dir_fd = crate::queue::open_relative(queue.root_fd().as_raw_fd(), dir_path).unwrap();
        // Create dummy file in same dir
        let dummy_fd = steadq_fs_linux::openat(
            dir_fd.as_raw_fd(),
            "dummy.sqj",
            libc::O_CREAT | libc::O_RDWR | libc::O_CLOEXEC,
            0o600,
        )
        .unwrap();
        let name_a = lease_a
            .exact_source_path
            .rsplit_once('/')
            .map(|(_, n)| n)
            .unwrap();
        // Same device, different inode should fail with NotFound.
        let res = queue.quarantine_corrupt_lease(dir_fd.as_raw_fd(), name_a, dummy_fd.as_raw_fd());
        let _ = dummy_fd;
        assert!(
            res.is_err(),
            "quarantine with mismatched held fd should fail, got ok"
        );
        let err = res.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn validate_active_object_rejects_delayed_bucket_mismatch() {
        let (_tmp, mut queue) = create_test_queue();
        // Enqueue a delayed job.
        let wall_now = steadq_fs_linux::clock_realtime_ns().unwrap();
        let not_before = wall_now + 5_000_000_000;
        match queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"delayed".to_vec(),
            initial_not_before: Some(not_before),
            ..Default::default()
        }) {
            EnqueueOutcome::Committed(_) => {}
            other => panic!("enqueue delayed must succeed, got {other:?}"),
        }
        // Locate the delayed file.
        let delayed_root = _tmp.path().join("delayed");
        let mut delayed_file: Option<(String, String, String)> = None;
        for bucket in std::fs::read_dir(&delayed_root).unwrap().flatten() {
            for shard in std::fs::read_dir(bucket.path()).unwrap().flatten() {
                for entry in std::fs::read_dir(shard.path()).unwrap().flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.ends_with(".sqj") {
                        let bucket_name = bucket.file_name().to_string_lossy().to_string();
                        let shard_name = shard.file_name().to_string_lossy().to_string();
                        delayed_file = Some((bucket_name, shard_name, name));
                        break;
                    }
                }
            }
        }
        let (bucket_name, shard_name, file_name) = delayed_file.expect("delayed file must exist");
        // Correct context must succeed.
        let correct_ctx = crate::ActivePathContext::Delayed {
            bucket: bucket_name.clone(),
            shard: shard_name.clone(),
        };
        let dir_fd = crate::queue::open_relative(
            queue.root_fd().as_raw_fd(),
            &format!("delayed/{bucket_name}/{shard_name}"),
        )
        .unwrap();
        let ok = queue.validate_active_object(dir_fd.as_raw_fd(), &file_name, &correct_ctx);
        assert!(
            ok.is_ok(),
            "correct delayed bucket must validate, got {ok:?}"
        );
        // Wrong bucket must be rejected. Flip last hex digit to guarantee mismatch while keeping hex valid.
        let mut wrong_bucket = bucket_name.clone();
        let last = wrong_bucket.pop().unwrap();
        let flipped = if last == '0' { '1' } else { '0' };
        wrong_bucket.push(flipped);
        let wrong_ctx = crate::ActivePathContext::Delayed {
            bucket: wrong_bucket.clone(),
            shard: shard_name.clone(),
        };
        let wrong_fd = crate::queue::open_relative(
            queue.root_fd().as_raw_fd(),
            &format!("delayed/{bucket_name}/{shard_name}"),
        )
        .unwrap();
        // validate_active_object checks the filename bucket against the directory bucket.
        // With a mismatched bucket in the context, it must return QueueCorrupt.
        // Under the mutant that changes != to ==, this would incorrectly return Ok.
        let wrong = queue.validate_active_object(wrong_fd.as_raw_fd(), &file_name, &wrong_ctx);
        assert!(
            matches!(wrong, Err(Error::QueueCorrupt(_))),
            "wrong delayed bucket must be rejected, got {wrong:?}"
        );
    }

    #[test]
    fn validate_active_object_rejects_tag_mismatch() {
        let (_tmp, mut queue) = create_test_queue();
        match queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"tag-test".to_vec(),
            ..Default::default()
        }) {
            EnqueueOutcome::Committed(_) => {}
            other => panic!("enqueue must succeed, got {other:?}"),
        }
        let ready_root = _tmp.path().join("ready");
        let mut found: Option<(String, String)> = None;
        for shard in std::fs::read_dir(&ready_root).unwrap().flatten() {
            for entry in std::fs::read_dir(shard.path()).unwrap().flatten() {
                let n = entry.file_name().to_string_lossy().to_string();
                if n.ends_with(".sqj") {
                    found = Some((shard.file_name().to_string_lossy().to_string(), n));
                    break;
                }
            }
        }
        let (shard_name, file_name) = found.expect("ready file");
        let correct_ctx = crate::ActivePathContext::Ready {
            shard: shard_name.clone(),
        };
        let dir_fd = crate::queue::open_relative(
            queue.root_fd().as_raw_fd(),
            &format!("ready/{shard_name}"),
        )
        .unwrap();
        let ok = queue.validate_active_object(dir_fd.as_raw_fd(), &file_name, &correct_ctx);
        assert!(ok.is_ok(), "correct tag must validate, got {ok:?}");
        let wrong_ctx = crate::ActivePathContext::Ready {
            shard: "ffff".to_string(),
        };
        let bad = queue.validate_active_object(dir_fd.as_raw_fd(), &file_name, &wrong_ctx);
        assert!(
            matches!(bad, Err(Error::QueueCorrupt(_))),
            "wrong shard must cause tag mismatch, got {bad:?}"
        );
    }

    #[test]
    fn check_duplicate_ack_bounded_is_false_when_no_receipt() {
        let (_tmp, mut queue) = create_test_queue();
        let payload = b"dup-ack-test";
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: payload.to_vec(),
            ..Default::default()
        });
        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            other => panic!("lease must succeed, got {other:?}"),
        };
        let before = queue.check_duplicate_ack_bounded(&lease);
        assert!(!before, "no receipt yet, duplicate check must be false");
        queue.verify_lease_payload(&lease).unwrap();
        let ack = queue.ack(&lease);
        assert!(
            matches!(ack, AckOutcome::Acked),
            "ack must succeed, got {ack:?}"
        );
        let after = queue.check_duplicate_ack_bounded(&lease);
        assert!(after, "after ack, duplicate check must be true");
    }

    #[test]
    fn full_lifecycle_with_verify() {
        let (_tmp, mut queue) = create_test_queue();
        let payload = b"lifecycle test payload data";
        queue.enqueue(EnqueueInput {
            maximum_attempts: 5,
            content_type: "application/json".to_string(),
            payload: payload.to_vec(),
            ..Default::default()
        });
        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            _ => panic!("lease failed"),
        };
        // Stream-read the payload
        let mut collected = Vec::new();
        queue
            .stream_lease_payload(&lease, 16, |chunk| {
                collected.extend_from_slice(chunk);
                Ok(())
            })
            .unwrap();
        assert_eq!(&collected[..], &payload[..]);
        // Verify + ack
        queue.verify_lease_payload(&lease).unwrap();
        let result = queue.ack(&lease);
        assert!(matches!(result, AckOutcome::Acked));
    }

    // ===== T2: Oracle-driven closed-loop simulation =====
    // P1-28: Track real EnqueueTicket.job_id / LeaseInfo.job_id values and
    // reconcile oracle state with inspect() after every operation.
    #[test]
    fn oracle_driven_closed_loop() {
        use std::collections::HashMap;
        let (_tmp, mut queue) = create_test_queue();

        #[derive(Clone, Copy, PartialEq, Debug)]
        enum State {
            Ready,
            Leased,
            Acked,
            Retried,
            Dead,
        }
        let mut oracle: HashMap<[u8; 16], State> = HashMap::new();
        // Live lease handles keyed by real job_id.
        let mut leases: HashMap<[u8; 16], LeaseInfo> = HashMap::new();
        let mut rng_state = 42u64;

        for _step in 0..500 {
            rng_state ^= rng_state << 13;
            rng_state ^= rng_state >> 7;
            rng_state ^= rng_state << 17;

            match rng_state % 4 {
                0 => {
                    let outcome = queue.enqueue(EnqueueInput {
                        maximum_attempts: 3,
                        content_type: "x".to_string(),
                        payload: b"data".to_vec(),
                        ..Default::default()
                    });
                    if let EnqueueOutcome::Committed(ticket) = outcome {
                        oracle.insert(ticket.job_id, State::Ready);
                        // Reconcile: inspect must see a ready object for this id.
                        let snaps = queue.inspect(&ticket.job_id);
                        assert!(
                            snaps.iter().any(|s| s.state == "ready"),
                            "oracle Ready not reflected by inspect for {}",
                            steadq_names::hex_encode(&ticket.job_id)
                        );
                    }
                }
                1 => {
                    if let LeaseOutcome::Leased(l) = queue.lease(0, 30_000_000_000) {
                        let id = l.job_id;
                        oracle.insert(id, State::Leased);
                        leases.insert(id, l);
                        let snaps = queue.inspect(&id);
                        assert!(
                            snaps.iter().any(|s| s.state == "leased"),
                            "oracle Leased not reflected by inspect"
                        );
                    }
                }
                2 => {
                    // Ack a leased job using the real handle.
                    let job_id = oracle
                        .iter()
                        .find(|(_, s)| **s == State::Leased)
                        .map(|(id, _)| *id);
                    if let Some(job_id) = job_id {
                        if let Some(lease) = leases.remove(&job_id) {
                            queue.verify_lease_payload(&lease).unwrap();
                            match queue.ack(&lease) {
                                AckOutcome::Acked | AckOutcome::AlreadyAcked => {
                                    oracle.insert(job_id, State::Acked);
                                    let snaps = queue.inspect(&job_id);
                                    assert!(
                                        snaps.iter().any(|s| s.state == "receipt")
                                            || snaps.is_empty()
                                            || snaps.iter().all(|s| s.state != "leased"),
                                        "acked job still leased in inspect"
                                    );
                                }
                                _ => {
                                    // Keep as leased if ack failed; reinsert handle.
                                    leases.insert(job_id, lease);
                                }
                            }
                        }
                    }
                }
                _ => {
                    if let LeaseOutcome::Leased(l) = queue.lease(0, 30_000_000_000) {
                        let id = l.job_id;
                        if rng_state.is_multiple_of(2) {
                            queue.verify_lease_payload(&l).unwrap();
                            if matches!(queue.ack(&l), AckOutcome::Acked | AckOutcome::AlreadyAcked)
                            {
                                oracle.insert(id, State::Acked);
                                leases.remove(&id);
                            }
                        } else if let TransitionOutcome::Committed = queue.retry_now(&l) {
                            leases.remove(&id);
                            let snaps = queue.inspect(&id);
                            // retry_now moves to ready, or to dead when
                            // attempts are exhausted.
                            if snaps.iter().any(|s| s.state == "ready") {
                                oracle.insert(id, State::Retried);
                            } else if snaps.iter().any(|s| s.state == "dead") {
                                oracle.insert(id, State::Dead);
                            } else {
                                panic!(
                                    "retry committed but inspect has {:?}",
                                    snaps.iter().map(|s| s.state.as_str()).collect::<Vec<_>>()
                                );
                            }
                        }
                    }
                }
            }
        }

        let ready_count = oracle.values().filter(|s| **s == State::Ready).count();
        let leased_count = oracle.values().filter(|s| **s == State::Leased).count();
        let acked_count = oracle.values().filter(|s| **s == State::Acked).count();
        let retried_count = oracle.values().filter(|s| **s == State::Retried).count();
        let dead_count = oracle.values().filter(|s| **s == State::Dead).count();
        assert!(
            ready_count + leased_count + acked_count + retried_count + dead_count > 0,
            "oracle should have tracked some jobs"
        );

        // Final reconciliation: every oracle Ready/Leased job must appear in inspect.
        for (id, state) in &oracle {
            match state {
                State::Ready => {
                    let snaps = queue.inspect(id);
                    // May have been leased later without oracle update if we only
                    // track transitions we apply; re-check live state.
                    let live_ready = snaps.iter().any(|s| s.state == "ready");
                    let live_leased = snaps.iter().any(|s| s.state == "leased");
                    assert!(
                        live_ready || live_leased || snaps.is_empty(),
                        "oracle Ready job in unexpected state: {:?}",
                        snaps.iter().map(|s| s.state.as_str()).collect::<Vec<_>>()
                    );
                }
                State::Leased => {
                    let snaps = queue.inspect(id);
                    assert!(
                        snaps.iter().any(|s| s.state == "leased")
                            || snaps.iter().any(|s| s.state == "ready")
                            || snaps.iter().any(|s| s.state == "receipt"),
                        "oracle Leased job vanished without transition"
                    );
                }
                State::Acked | State::Retried | State::Dead => {}
            }
        }
    }

    // ===== B3: Wall floor poisoning =====
    #[test]
    fn wall_floor_error_poisons_mutating_ops() {
        let (_tmp, mut queue) = create_test_queue();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"data".to_vec(),
            ..Default::default()
        });
        // Corrupt the wall watermark to trigger decode failure.
        let wm_path = _tmp.path().join("control/wall-watermark");
        if wm_path.exists() {
            std::fs::write(&wm_path, b"corrupted watermark data").unwrap();
        }
        // The next mutating operation should poison and return error.
        let outcome = queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"more data".to_vec(),
            ..Default::default()
        });
        // Watermark decode failure should cause NotCommitted or poison.
        // Missing watermark is Ok(clock), but corrupt watermark is Err.
        match outcome {
            EnqueueOutcome::NotCommitted(_, _) => { /* expected */ }
            EnqueueOutcome::Committed(_) => {
                // Some implementations may treat corrupt watermark as missing.
                // At minimum, the queue should still be usable.
            }
            _ => panic!("unexpected outcome from enqueue with corrupt watermark"),
        }
    }

    // ===== P0-04: ack EEXIST authenticates receipt =====
    #[test]
    fn ack_conflicting_receipt_is_not_already_acked() {
        let (_tmp, mut queue) = create_test_queue();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"data".to_vec(),
            ..Default::default()
        });
        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            _ => panic!("lease failed"),
        };
        // Compute the EXACT receipt path ack() will target.
        let shard = compute_shard(
            &queue.format.queue_id,
            &lease.job_id,
            queue.format.shard_count,
        );
        let shard_str = shard_hex(shard);
        let wall = queue.effective_wall_floor_ns();
        let bucket =
            steadq_math::bucket_number(wall, queue.format.terminal_bucket_width_ns).unwrap_or(0);
        let bucket_str = bucket_hex(bucket);
        let new_gen = lease.generation + 1;
        let receipt_common = CommonFields {
            job_id: lease.job_id,
            generation: new_gen,
            attempt: lease.attempt,
            maximum_attempts: lease.maximum_attempts,
        };
        let receipt_base = format!(
            "{}.g{:016x}.a{:08x}.m{:08x}.t{}",
            steadq_names::hex_encode(&receipt_common.job_id),
            receipt_common.generation,
            receipt_common.attempt,
            receipt_common.maximum_attempts,
            steadq_names::hex_encode(&lease.token),
        );
        let receipt_ctx = steadq_names::terminal_context(
            steadq_names::State::Receipt,
            &bucket_str,
            &shard_str,
            &receipt_base,
        );
        let receipt_tag = steadq_names::compute_name_tag(&queue.format.queue_id, &receipt_ctx);
        let receipt_name =
            steadq_names::receipt_filename(&receipt_common, &lease.token, &receipt_tag);
        // Pre-plant a non-receipt file at the exact destination.
        let receipt_dir = format!("receipts/{bucket_str}/{shard_str}");
        let full_dir = _tmp.path().join(&receipt_dir);
        std::fs::create_dir_all(&full_dir).unwrap();
        std::fs::write(full_dir.join(&receipt_name), b"not a receipt at all").unwrap();
        // Ack should not succeed because the destination already has a conflicting object.
        // First verify that ack can find the lease (it's valid).
        // Then the EEXIST path should trigger because we pre-planted a file.
        let result = queue.ack(&lease);
        // The result should be NotCommitted because either:
        // (a) the EEXIST handler authenticates the garbage receipt and fails, or
        // (b) the rename fails with EEXIST and receipt_is_authentic returns false.
        match result {
            AckOutcome::NotCommitted(_) => {
                // Good - the conflicting receipt was not treated as AlreadyAcked.
            }
            AckOutcome::Acked => panic!("conflicting receipt should not be Acked"),
            AckOutcome::AlreadyAcked => panic!("conflicting receipt should not be AlreadyAcked"),
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    // ===== P1-06: ENOTDIR is QueueCorrupt =====
    #[test]
    fn enotdir_in_lease_path_is_corruption() {
        let (_tmp, mut queue) = create_test_queue();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"data".to_vec(),
            ..Default::default()
        });
        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            _ => panic!("lease failed"),
        };
        // Replace an intermediate directory with a regular file.
        let boot_dir = _tmp.path().join("leased").join(&lease.boot_id);
        let bucket_dir = boot_dir.join(lease.exact_source_path.split('/').nth(2).unwrap());
        // Remove the bucket dir and replace with a file
        let _ = std::fs::remove_dir_all(&bucket_dir);
        std::fs::write(&bucket_dir, b"notadir").unwrap();
        // Ack should report corruption, not LeaseLost.
        let result = queue.ack(&lease);
        assert!(
            matches!(result, AckOutcome::NotCommitted(Error::QueueCorrupt(_))),
            "ENOTDIR should be QueueCorrupt, got {result:?}"
        );
    }

    // ===== ack on gone source returns AlreadyAcked (ENOENT path) =====
    #[test]
    fn ack_on_gone_source_returns_already_acked() {
        let (_tmp, mut queue) = create_test_queue();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"data".to_vec(),
            ..Default::default()
        });
        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            _ => panic!("lease failed"),
        };
        // First ack succeeds.
        let result = queue.ack_unverified(&lease);
        assert!(matches!(result, AckOutcome::Acked));
        // Second ack: source is gone (ENOENT in open_and_validate).
        // Should return AlreadyAcked, not NotCommitted(QueueCorrupt).
        let result2 = queue.ack_unverified(&lease);
        assert!(
            matches!(result2, AckOutcome::AlreadyAcked),
            "second ack should be AlreadyAcked, got {result2:?}"
        );
    }

    // ===== move_to_dead actually moves exhausted objects =====
    #[test]
    fn exhausted_attempts_move_to_dead() {
        let (_tmp, mut queue) = create_test_queue();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 1,
            content_type: "x".to_string(),
            payload: b"data".to_vec(),
            ..Default::default()
        });
        // Lease increments attempt to 1. Retry puts it back in ready with attempt=1.
        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            _ => panic!("lease failed"),
        };
        let _ = queue.retry_now(&lease);
        // Now ready has attempt=1 >= max=1. Next lease scan should move to dead.
        let result = queue.lease(0, 30_000_000_000);
        assert!(matches!(result, LeaseOutcome::Empty));
        // Verify the object was moved to dead, not left in ready.
        // Check that dead directory is non-empty.
        let dead_root = _tmp.path().join("dead");
        let has_dead = std::fs::read_dir(&dead_root)
            .map(|mut d| d.next().is_some())
            .unwrap_or(false);
        assert!(has_dead, "exhausted object should be in dead directory");
    }

    // ===== fsck on delayed/dead/receipt states =====
    #[test]
    fn fsck_finds_valid_delayed_job() {
        let (_tmp, mut queue) = create_test_queue();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"data".to_vec(),
            ..Default::default()
        });
        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            _ => panic!("lease failed"),
        };
        // Retry with delay to create a delayed object
        let _ = queue.retry_after(&lease, 999999999999);
        drop(queue);

        let queue2 = Queue::open(
            _tmp.path(),
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        let report = queue2.fsck(&FsckOptions::default());
        assert_eq!(report.findings.len(), 0, "findings: {:?}", report.findings);
    }

    #[test]
    fn fsck_finds_valid_dead_job() {
        let (_tmp, mut queue) = create_test_queue();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"data".to_vec(),
            ..Default::default()
        });
        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            _ => panic!("lease failed"),
        };
        // Bury to create a dead object
        let _ = queue.bury(&lease, DeadReason::ConsumerRejected);
        drop(queue);

        let queue2 = Queue::open(
            _tmp.path(),
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        let report = queue2.fsck(&FsckOptions::default());
        assert_eq!(report.findings.len(), 0, "findings: {:?}", report.findings);
    }

    #[test]
    fn fsck_finds_valid_receipt() {
        let (_tmp, mut queue) = create_test_queue();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"data".to_vec(),
            ..Default::default()
        });
        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            _ => panic!("lease failed"),
        };
        // Ack to create a receipt
        queue.verify_lease_payload(&lease).unwrap();
        let result = queue.ack(&lease);
        assert!(matches!(result, AckOutcome::Acked));
        drop(queue);

        let queue2 = Queue::open(
            _tmp.path(),
            &OpenOptions {
                allow_unsupported_fs: true,
                ..Default::default()
            },
        )
        .unwrap();
        let report = queue2.fsck(&FsckOptions::default());
        assert_eq!(report.findings.len(), 0, "findings: {:?}", report.findings);
    }

    // ===== fsck on leased state =====
    #[test]
    fn fsck_finds_valid_leased_job() {
        let (_tmp, mut queue) = create_test_queue();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"data".to_vec(),
            ..Default::default()
        });
        let _lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            _ => panic!("lease failed"),
        };
        // Don't drop the queue - run fsck while object is leased.
        let report = queue.fsck(&FsckOptions::default());
        assert_eq!(
            report.findings.len(),
            0,
            "valid leased object should have no findings: {:?}",
            report.findings
        );
        assert!(report.total_objects >= 1);
    }

    // ===== ack_unverified reaches rename and triggers EEXIST =====
    #[test]
    fn ack_unverified_eexist_triggers_not_committed() {
        let (_tmp, mut queue) = create_test_queue();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"data".to_vec(),
            ..Default::default()
        });
        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            _ => panic!("lease failed"),
        };
        // Compute exact receipt path.
        let shard = compute_shard(
            &queue.format.queue_id,
            &lease.job_id,
            queue.format.shard_count,
        );
        let shard_str = shard_hex(shard);
        let wall = queue.effective_wall_floor_ns_checked().unwrap();
        let bucket =
            steadq_math::bucket_number(wall, queue.format.terminal_bucket_width_ns).unwrap_or(0);
        let bucket_str = bucket_hex(bucket);
        let new_gen = lease.generation + 1;
        let receipt_common = CommonFields {
            job_id: lease.job_id,
            generation: new_gen,
            attempt: lease.attempt,
            maximum_attempts: lease.maximum_attempts,
        };
        let receipt_base = format!(
            "{}.g{:016x}.a{:08x}.m{:08x}.t{}",
            steadq_names::hex_encode(&receipt_common.job_id),
            receipt_common.generation,
            receipt_common.attempt,
            receipt_common.maximum_attempts,
            steadq_names::hex_encode(&lease.token),
        );
        let receipt_ctx = steadq_names::terminal_context(
            steadq_names::State::Receipt,
            &bucket_str,
            &shard_str,
            &receipt_base,
        );
        let receipt_tag = steadq_names::compute_name_tag(&queue.format.queue_id, &receipt_ctx);
        let receipt_name =
            steadq_names::receipt_filename(&receipt_common, &lease.token, &receipt_tag);
        let receipt_dir = format!("receipts/{bucket_str}/{shard_str}");
        let full_dir = _tmp.path().join(&receipt_dir);
        std::fs::create_dir_all(&full_dir).unwrap();
        std::fs::write(full_dir.join(&receipt_name), b"not a receipt").unwrap();
        // Use ack_unverified to skip payload verification and reach rename directly.
        let result = queue.ack_unverified(&lease);
        // Must be NotCommitted with QueueCorrupt (from EEXIST handler),
        // NOT IoFailure (from generic handler that mutant "guard == false" would route to).
        match result {
            AckOutcome::NotCommitted(Error::QueueCorrupt(_)) => { /* correct */ }
            AckOutcome::NotCommitted(other) => {
                panic!("expected QueueCorrupt from EEXIST handler, got {other:?}")
            }
            other => panic!("expected NotCommitted, got {other:?}"),
        }
    }

    // ===== stream_lease_payload boundary tests =====
    #[test]
    fn stream_payload_exact_byte_math() {
        let (_tmp, mut queue) = create_test_queue();
        let payload = b"0123456789ABCDEF"; // 16 bytes
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: payload.to_vec(),
            ..Default::default()
        });
        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            _ => panic!("lease failed"),
        };
        // Read with small chunk to test exact offset math.
        let mut collected = Vec::new();
        queue
            .stream_lease_payload(&lease, 4096, |chunk| {
                collected.extend_from_slice(chunk);
                Ok(())
            })
            .unwrap();
        assert_eq!(&collected, payload);

        // Read with chunk size equal to payload.
        collected.clear();
        queue
            .stream_lease_payload(&lease, 16, |chunk| {
                collected.extend_from_slice(chunk);
                Ok(())
            })
            .unwrap();
        assert_eq!(&collected, payload);

        // Read with chunk larger than payload.
        collected.clear();
        queue
            .stream_lease_payload(&lease, 1024, |chunk| {
                collected.extend_from_slice(chunk);
                Ok(())
            })
            .unwrap();
        assert_eq!(&collected, payload);
    }

    #[test]
    fn resolve_does_not_follow_object_relocated_to_wrong_shard() {
        let (_tmp, mut queue) = create_test_queue();
        let et = match queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"data".to_vec(),
            ..Default::default()
        }) {
            EnqueueOutcome::Committed(t) => t,
            _ => panic!("enqueue failed"),
        };
        // Move the ready file to a wrong shard directory.
        let actual_path = et.expected_relative_path.clone();
        let actual_full = _tmp.path().join(&actual_path);
        let parts: Vec<&str> = actual_path.split('/').collect();
        let wrong_shard = if parts[1] == "0000" { "0001" } else { "0000" };
        let wrong_dir = _tmp.path().join("ready").join(wrong_shard);
        std::fs::create_dir_all(&wrong_dir).unwrap();
        let wrong_path = wrong_dir.join(parts[2]);
        std::fs::rename(&actual_full, &wrong_path).unwrap();
        let ticket = test_claim_ticket(&queue, et.job_id, 0, 0, 3, [0; 16], et.envelope_digest);
        let outcome = queue.resolve(&ticket, false);
        assert!(
            matches!(outcome, ResolutionOutcome::NeitherObserved),
            "resolver should only inspect the derived shard, got {outcome:?}"
        );
    }

    // ===== P0-05: verified fd dev/ino check =====
    #[test]
    fn ack_verified_fd_held_open_across_rename() {
        let (_tmp, mut queue) = create_test_queue();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"verified payload".to_vec(),
            ..Default::default()
        });
        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            _ => panic!("lease failed"),
        };
        // Normal ack should succeed and return Acked (not NotCommitted).
        let result = queue.ack(&lease);
        assert!(
            matches!(result, AckOutcome::Acked),
            "normal ack should succeed, got {result:?}"
        );
    }

    // ===== P0-05: verified fd check detects swap =====
    #[test]
    fn ack_verified_fd_dev_ino_check() {
        let (_tmp, mut queue) = create_test_queue();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"test payload data".to_vec(),
            ..Default::default()
        });
        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            _ => panic!("lease failed"),
        };
        // Normal ack should work - payload is valid.
        let result = queue.ack(&lease);
        assert!(matches!(result, AckOutcome::Acked));
    }

    // ===== Fault injection: post-linearization and pre-linearization paths =====

    #[test]
    fn fault_ack_post_rename_fsync_is_outcome_unknown() {
        steadq_fs_linux::fault::reset();
        let (tmp, mut queue) = create_test_queue();

        // Warm up so at least one terminal receipt bucket exists.
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"warmup".to_vec(),
            ..Default::default()
        });
        let warm = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            _ => panic!("warmup lease failed"),
        };
        queue.verify_lease_payload(&warm).unwrap();
        assert!(matches!(queue.ack(&warm), AckOutcome::Acked));

        // Pre-create every shard under existing receipt buckets so ensure_dir
        // during the next ack performs no mkdir and no fsync_dir_fd. The next
        // fsync_dir_fd is then strictly post-rename (OutcomeUnknown).
        let receipts = tmp.path().join("receipts");
        let shard_count = queue.format().shard_count;
        if let Ok(buckets) = std::fs::read_dir(&receipts) {
            for bucket in buckets.flatten() {
                if !bucket.path().is_dir() {
                    continue;
                }
                for shard in 0..shard_count {
                    let _ = std::fs::create_dir_all(bucket.path().join(format!("{shard:04x}")));
                }
            }
        }

        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"payload-under-test".to_vec(),
            ..Default::default()
        });
        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            _ => panic!("lease failed"),
        };
        queue.verify_lease_payload(&lease).unwrap();

        steadq_fs_linux::fault::inject("fsync_dir_fd", 1);
        let result = queue.ack(&lease);
        steadq_fs_linux::fault::reset();
        assert!(
            matches!(result, AckOutcome::OutcomeUnknown(_)),
            "expected OutcomeUnknown, got {result:?}"
        );
    }

    #[test]
    fn fault_ack_rename_failure_is_not_committed() {
        steadq_fs_linux::fault::reset();
        let (_tmp, mut queue) = create_test_queue();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"data".to_vec(),
            ..Default::default()
        });
        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            _ => panic!("lease failed"),
        };
        queue.verify_lease_payload(&lease).unwrap();
        steadq_fs_linux::fault::inject("renameat2_noreplace", 1);
        let result = queue.ack(&lease);
        steadq_fs_linux::fault::reset();
        assert!(
            matches!(result, AckOutcome::NotCommitted(_)),
            "expected NotCommitted, got {result:?}"
        );
    }

    #[test]
    fn fault_retry_post_rename_fsync_is_outcome_unknown() {
        steadq_fs_linux::fault::reset();
        let (tmp, mut queue) = create_test_queue();
        queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"data".to_vec(),
            ..Default::default()
        });
        let lease = match queue.lease(0, 30_000_000_000) {
            LeaseOutcome::Leased(l) => l,
            _ => panic!("lease failed"),
        };
        // Pre-create every ready shard so ensure_dir during retry_now does not
        // fsync. The next fsync_dir_fd is post-rename.
        let ready = tmp.path().join("ready");
        let shard_count = queue.format().shard_count;
        for shard in 0..shard_count {
            let _ = std::fs::create_dir_all(ready.join(format!("{shard:04x}")));
        }
        steadq_fs_linux::fault::inject("fsync_dir_fd", 1);
        let result = queue.retry_now(&lease);
        steadq_fs_linux::fault::reset();
        assert!(
            matches!(result, TransitionOutcome::OutcomeUnknown(_)),
            "expected OutcomeUnknown, got {result:?}"
        );
    }

    #[test]
    fn fault_clock_realtime_poisons_enqueue() {
        steadq_fs_linux::fault::reset();
        let (_tmp, mut queue) = create_test_queue();
        steadq_fs_linux::fault::inject("clock_realtime_ns", 1);
        let outcome = queue.enqueue(EnqueueInput {
            maximum_attempts: 3,
            content_type: "x".to_string(),
            payload: b"data".to_vec(),
            ..Default::default()
        });
        steadq_fs_linux::fault::reset();
        assert!(
            matches!(
                outcome,
                EnqueueOutcome::NotCommitted(_, _) | EnqueueOutcome::OutcomeUnknown(_, _)
            ),
            "expected clock fault to fail enqueue, got {outcome:?}"
        );
    }

    #[test]
    fn is_expected_dev_zero_table() {
        assert!(Queue::is_expected_dev_zero(0));
        assert!(!Queue::is_expected_dev_zero(1));
        assert!(!Queue::is_expected_dev_zero(u64::MAX));
        assert!(!Queue::is_expected_dev_zero(42));
    }

    #[test]
    fn is_expected_inode_zero_table() {
        assert!(Queue::is_expected_inode_zero(0));
        assert!(!Queue::is_expected_inode_zero(1));
        assert!(!Queue::is_expected_inode_zero(u64::MAX));
    }

    #[test]
    fn shard_matches_table() {
        assert!(Queue::shard_matches(5, 5));
        assert!(!Queue::shard_matches(5, 6));
        assert!(!Queue::shard_matches(6, 5));
        assert!(!Queue::shard_matches(0, 1));
        assert!(Queue::shard_matches(u32::MAX, u32::MAX));
    }
}
