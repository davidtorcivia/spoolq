// Typed physical locations for queue objects.

use steadq_names::{self, bucket_hex, shard_hex, CommonFields};

use crate::errors::Error;

/// Typed location of a queue object on disk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Location {
    Ready {
        shard: u32,
    },
    Leased {
        boot_id: String,
        bucket: u64,
        shard: u32,
    },
    Delayed {
        bucket: u64,
        shard: u32,
    },
    Receipt {
        bucket: u64,
        shard: u32,
    },
    Dead {
        bucket: u64,
        shard: u32,
    },
}

/// Target filename plus its typed location.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Target {
    pub location: Location,
    pub filename: String,
}

impl Target {
    pub fn directory(&self) -> String {
        match &self.location {
            Location::Ready { shard } => format!("ready/{}", shard_hex(*shard)),
            Location::Leased {
                boot_id,
                bucket,
                shard,
            } => {
                format!(
                    "leased/{}/{}/{}",
                    boot_id,
                    bucket_hex(*bucket),
                    shard_hex(*shard)
                )
            }
            Location::Delayed { bucket, shard } => {
                format!("delayed/{}/{}", bucket_hex(*bucket), shard_hex(*shard))
            }
            Location::Receipt { bucket, shard } => {
                format!("receipts/{}/{}", bucket_hex(*bucket), shard_hex(*shard))
            }
            Location::Dead { bucket, shard } => {
                format!("dead/{}/{}", bucket_hex(*bucket), shard_hex(*shard))
            }
        }
    }

    pub fn relative_path(&self) -> String {
        format!("{}/{}", self.directory(), self.filename)
    }

    pub fn state(&self) -> steadq_names::State {
        match self.location {
            Location::Ready { .. } => steadq_names::State::Ready,
            Location::Leased { .. } => steadq_names::State::Leased,
            Location::Delayed { .. } => steadq_names::State::Delayed,
            Location::Receipt { .. } => steadq_names::State::Receipt,
            Location::Dead { .. } => steadq_names::State::Dead,
        }
    }
}

/// Layout helper that owns queue configuration for path construction.
pub struct Layout<'a> {
    queue_id: &'a [u8; 16],
    shard_count: u32,
    lease_bucket_width_ns: u64,
    delayed_bucket_width_ns: u64,
    terminal_bucket_width_ns: u64,
    boot_id: &'a str,
}

impl<'a> Layout<'a> {
    pub fn new(
        queue_id: &'a [u8; 16],
        shard_count: u32,
        lease_bucket_width_ns: u64,
        delayed_bucket_width_ns: u64,
        terminal_bucket_width_ns: u64,
        boot_id: &'a str,
    ) -> Self {
        Self {
            queue_id,
            shard_count,
            lease_bucket_width_ns,
            delayed_bucket_width_ns,
            terminal_bucket_width_ns,
            boot_id,
        }
    }

    fn shard_for(&self, job_id: &[u8; 16]) -> u32 {
        steadq_names::compute_shard(self.queue_id, job_id, self.shard_count)
    }

    pub fn ready(&self, common: &CommonFields) -> Target {
        let shard = self.shard_for(&common.job_id);
        let filename = steadq_names::make_ready_name(self.queue_id, &shard_hex(shard), common);
        Target {
            location: Location::Ready { shard },
            filename,
        }
    }

    pub fn delayed(&self, common: &CommonFields, not_before_ns: u64) -> Result<Target, Error> {
        let (bucket, _) =
            steadq_math::eligibility_bucket_and_ns(not_before_ns, self.delayed_bucket_width_ns)
                .ok_or_else(|| Error::InvalidInput("eligibility overflow".into()))?;
        let shard = self.shard_for(&common.job_id);
        let filename = steadq_names::make_delayed_name(
            self.queue_id,
            &bucket_hex(bucket),
            &shard_hex(shard),
            common,
            not_before_ns,
        );
        Ok(Target {
            location: Location::Delayed { bucket, shard },
            filename,
        })
    }

    pub fn leased(
        &self,
        common: &CommonFields,
        boottime_deadline_ns: u64,
        wall_deadline_ns: u64,
        token: &[u8; 16],
    ) -> Result<Target, Error> {
        self.leased_for_boot(
            common,
            self.boot_id,
            boottime_deadline_ns,
            wall_deadline_ns,
            token,
        )
    }

    pub fn leased_for_boot(
        &self,
        common: &CommonFields,
        boot_id: &str,
        boottime_deadline_ns: u64,
        wall_deadline_ns: u64,
        token: &[u8; 16],
    ) -> Result<Target, Error> {
        let bucket = steadq_math::lease_bucket(boottime_deadline_ns, self.lease_bucket_width_ns)
            .unwrap_or(0);
        let shard = self.shard_for(&common.job_id);
        let filename = steadq_names::make_leased_name(
            self.queue_id,
            boot_id,
            &bucket_hex(bucket),
            &shard_hex(shard),
            common,
            boottime_deadline_ns,
            wall_deadline_ns,
            token,
        );
        Ok(Target {
            location: Location::Leased {
                boot_id: boot_id.to_string(),
                bucket,
                shard,
            },
            filename,
        })
    }

    pub fn receipt(
        &self,
        common: &CommonFields,
        token: &[u8; 16],
        wall_ns: u64,
    ) -> Result<Target, Error> {
        let bucket =
            steadq_math::bucket_number(wall_ns, self.terminal_bucket_width_ns).unwrap_or(0);
        Ok(self.receipt_in_bucket(common, token, bucket))
    }

    pub fn receipt_in_bucket(
        &self,
        common: &CommonFields,
        token: &[u8; 16],
        bucket: u64,
    ) -> Target {
        let shard = self.shard_for(&common.job_id);
        let filename = steadq_names::make_receipt_name(
            self.queue_id,
            &bucket_hex(bucket),
            &shard_hex(shard),
            common,
            token,
        );
        Target {
            location: Location::Receipt { bucket, shard },
            filename,
        }
    }

    pub fn dead(&self, common: &CommonFields, reason: u16, wall_ns: u64) -> Result<Target, Error> {
        let bucket =
            steadq_math::bucket_number(wall_ns, self.terminal_bucket_width_ns).unwrap_or(0);
        Ok(self.dead_in_bucket(common, reason, bucket))
    }

    pub fn dead_in_bucket(&self, common: &CommonFields, reason: u16, bucket: u64) -> Target {
        let shard = self.shard_for(&common.job_id);
        let filename = steadq_names::make_dead_name(
            self.queue_id,
            &bucket_hex(bucket),
            &shard_hex(shard),
            common,
            reason,
        );
        Target {
            location: Location::Dead { bucket, shard },
            filename,
        }
    }

    fn is_valid_leased_path_parts(len: usize, first: &str) -> bool {
        len == 5 && first == "leased"
    }

    fn is_shard_in_range(shard: u32, count: u32) -> bool {
        shard < count
    }

    /// Parse a leased relative path into typed location and filename.
    /// Validates leased/<boot>/<bucket>/<shard>/<name> with canonical hex.
    pub fn parse_leased_path(&self, relative: &str) -> Result<(Location, String), Error> {
        let parts: Vec<&str> = relative.split('/').collect();
        if !Self::is_valid_leased_path_parts(parts.len(), parts[0]) {
            return Err(Error::QueueCorrupt("invalid leased path".into()));
        }
        let boot_id = parts[1];
        if steadq_names::boot_id_bytes(boot_id).is_none() {
            return Err(Error::QueueCorrupt("invalid boot id".into()));
        }
        let bucket = steadq_names::bucket_from_hex(parts[2])
            .ok_or_else(|| Error::QueueCorrupt("invalid bucket hex".into()))?;
        let shard = steadq_names::shard_from_hex(parts[3])
            .ok_or_else(|| Error::QueueCorrupt("invalid shard hex".into()))?;
        if !Self::is_shard_in_range(shard, self.shard_count) {
            return Err(Error::QueueCorrupt("shard out of range".into()));
        }
        let filename = parts[4].to_string();
        let loc = Location::Leased {
            boot_id: boot_id.to_string(),
            bucket,
            shard,
        };
        Ok((loc, filename))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_layout() -> Layout<'static> {
        static QID: [u8; 16] = [0x42; 16];
        static BOOT: &str = "12345678-1234-1234-1234-123456789abc";
        Layout::new(
            &QID,
            64,
            10_000_000_000,
            10_000_000_000,
            3_600_000_000_000,
            BOOT,
        )
    }

    #[test]
    fn parse_leased_path_valid() {
        let layout = test_layout();
        let path = "leased/12345678-1234-1234-1234-123456789abc/000000000000000a/0001/file.sqj";
        let (loc, name) = layout.parse_leased_path(path).expect("valid must parse");
        match loc {
            Location::Leased {
                boot_id,
                bucket,
                shard,
            } => {
                assert_eq!(boot_id, "12345678-1234-1234-1234-123456789abc");
                assert_eq!(bucket, 0xa);
                assert_eq!(shard, 1);
            }
            _ => panic!("expected Leased"),
        }
        assert_eq!(name, "file.sqj");
    }

    #[test]
    fn parse_leased_path_rejects_wrong_length() {
        let layout = test_layout();
        let short = "leased/12345678-1234-1234-1234-123456789abc/000000000000000a/0001";
        assert!(layout.parse_leased_path(short).is_err());
        let long =
            "leased/12345678-1234-1234-1234-123456789abc/000000000000000a/0001/file.sqj/extra";
        assert!(layout.parse_leased_path(long).is_err());
    }

    #[test]
    fn parse_leased_path_rejects_wrong_prefix() {
        let layout = test_layout();
        let wrong = "ready/12345678-1234-1234-1234-123456789abc/000000000000000a/0001/file.sqj";
        assert!(layout.parse_leased_path(wrong).is_err());
    }

    #[test]
    fn parse_leased_path_rejects_short_but_correct_prefix() {
        let layout = test_layout();
        let short_correct_prefix = "leased/12345678-1234-1234-1234-123456789abc/000000000000000a";
        assert!(layout.parse_leased_path(short_correct_prefix).is_err());
    }

    #[test]
    fn parse_leased_path_rejects_shard_out_of_range() {
        let layout = test_layout();
        let bad_shard =
            "leased/12345678-1234-1234-1234-123456789abc/000000000000000a/ffff/file.sqj";
        assert!(layout.parse_leased_path(bad_shard).is_err());
    }

    #[test]
    fn is_valid_leased_path_parts_table() {
        assert!(Layout::is_valid_leased_path_parts(5, "leased"));
        assert!(!Layout::is_valid_leased_path_parts(4, "leased"));
        assert!(!Layout::is_valid_leased_path_parts(5, "ready"));
        assert!(!Layout::is_valid_leased_path_parts(6, "leased"));
        assert!(!Layout::is_valid_leased_path_parts(5, "Leased"));
        assert!(!Layout::is_valid_leased_path_parts(0, ""));
    }

    #[test]
    fn is_shard_in_range_table() {
        assert!(Layout::is_shard_in_range(0, 64));
        assert!(Layout::is_shard_in_range(63, 64));
        assert!(!Layout::is_shard_in_range(64, 64));
        assert!(!Layout::is_shard_in_range(100, 64));
        assert!(Layout::is_shard_in_range(0, 1));
        assert!(!Layout::is_shard_in_range(1, 1));
        assert!(!Layout::is_shard_in_range(u32::MAX, 64));
    }
}
