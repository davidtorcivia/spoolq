// SteadQ/1 error and outcome types.

/// Error categories for all operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("not committed: {0}")]
    NotCommitted(String),
    #[error("resource exhausted")]
    ResourceExhausted,
    #[error("state exhausted")]
    StateExhausted,
    #[error("identity collision")]
    IdentityCollision,
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("invalid transition ticket: {0}")]
    InvalidTicket(String),
    #[error("unsupported filesystem")]
    UnsupportedFilesystem,
    #[error("unsupported format")]
    UnsupportedFormat,
    #[error("invalid clock")]
    InvalidClock,
    #[error("maintenance busy")]
    MaintenanceBusy,
    #[error("queue corrupt: {0}")]
    QueueCorrupt(String),
    #[error("payload corrupt")]
    PayloadCorrupt,
    #[error("queue poisoned: {0}")]
    QueuePoisoned(String),
    #[error("permission denied")]
    PermissionDenied,
    #[error("io failure: {0}")]
    IoFailure(String),
}

/// Operation result for mutations. Every mutating operation returns one of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationResult {
    Committed,
    NotCommitted(Error),
    OutcomeUnknown(TransitionTicket),
}

/// Enqueue outcomes.
#[derive(Debug, Clone)]
pub enum EnqueueOutcome {
    Committed(EnqueueTicket),
    NotCommitted(EnqueueTicket, Error),
    OutcomeUnknown(EnqueueTicket, Error),
}

/// Lease outcomes.
#[derive(Debug, Clone)]
pub enum LeaseOutcome {
    Leased(LeaseInfo),
    Empty,
    NotCommitted(Error),
    OutcomeUnknown(TransitionTicket),
}

/// Renew outcomes.
#[derive(Debug, Clone)]
pub enum RenewOutcome {
    Renewed(LeaseInfo),
    LeaseLost,
    NotCommitted(Error),
    OutcomeUnknown(TransitionTicket),
}

/// Ack outcomes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AckOutcome {
    Acked,
    AlreadyAcked,
    LeaseLost,
    NotCommitted(Error),
    OutcomeUnknown(TransitionTicket),
}

/// Transition outcomes (retry, bury).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionOutcome {
    Committed,
    LeaseLost,
    NotCommitted(Error),
    OutcomeUnknown(TransitionTicket),
}

/// Ticket for resolving an indeterminate enqueue.
#[derive(Debug, Clone)]
pub struct EnqueueTicket {
    pub job_id: [u8; 16],
    pub envelope_digest: [u8; 32],
    pub expected_initial_state: InitialState,
    pub expected_relative_path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitialState {
    Ready,
    Delayed,
}

pub const TRANSITION_TICKET_SCHEMA: &str = "steadq-transition-ticket";
pub const TRANSITION_TICKET_VERSION: u16 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionOperation {
    Claim,
    Renew,
    Acknowledge,
    RetryNow,
    RetryLater,
    Bury,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionPhase {
    Linearized,
    DestinationDirectoryDurable,
    SourceDirectoryDurable,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum TicketSource {
    Ready {},
    Leased {
        boot_id: String,
        boottime_deadline_ns: u64,
        wall_deadline_ns: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum TicketDestination {
    Ready {},
    Leased {
        boot_id: String,
        boottime_deadline_ns: u64,
        wall_deadline_ns: u64,
    },
    Delayed {
        not_before_ns: u64,
    },
    Receipt {
        terminal_bucket: u64,
    },
    Dead {
        terminal_bucket: u64,
        reason: u16,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TicketEvidence {
    pub(crate) envelope_digest: [u8; 32],
    pub(crate) payload_length: u64,
}

impl TicketEvidence {
    pub(crate) fn new(envelope_digest: [u8; 32], payload_length: u64) -> Self {
        Self {
            envelope_digest,
            payload_length,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TicketIdentity {
    job_id: [u8; 16],
    generation: u64,
    attempt: u32,
    maximum_attempts: u32,
    lease_token: [u8; 16],
    evidence: TicketEvidence,
}

impl TicketIdentity {
    pub(crate) fn new(
        job_id: [u8; 16],
        generation: u64,
        attempt: u32,
        maximum_attempts: u32,
        lease_token: [u8; 16],
        evidence: TicketEvidence,
    ) -> Self {
        Self {
            job_id,
            generation,
            attempt,
            maximum_attempts,
            lease_token,
            evidence,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionTicket {
    queue_id: [u8; 16],
    operation: TransitionOperation,
    phase: TransitionPhase,
    job_id: [u8; 16],
    source_generation: u64,
    source_attempt: u32,
    maximum_attempts: u32,
    lease_token: [u8; 16],
    envelope_digest: [u8; 32],
    payload_length: u64,
    source: TicketSource,
    destination: TicketDestination,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TransitionTicketWire {
    schema: String,
    version: u16,
    queue_id: String,
    operation: TransitionOperation,
    phase: TransitionPhase,
    source_identity: TicketIdentityWire,
    source: TicketSource,
    destination_derivation: TicketDestination,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TicketIdentityWire {
    job_id: String,
    generation: u64,
    attempt: u32,
    maximum_attempts: u32,
    lease_token: String,
    envelope_digest: String,
    payload_length: u64,
}

impl TransitionTicket {
    pub(crate) fn new(
        queue_id: [u8; 16],
        operation: TransitionOperation,
        phase: TransitionPhase,
        identity: TicketIdentity,
        source: TicketSource,
        destination: TicketDestination,
    ) -> Result<Self, Error> {
        let ticket = Self {
            queue_id,
            operation,
            phase,
            job_id: identity.job_id,
            source_generation: identity.generation,
            source_attempt: identity.attempt,
            maximum_attempts: identity.maximum_attempts,
            lease_token: identity.lease_token,
            envelope_digest: identity.evidence.envelope_digest,
            payload_length: identity.evidence.payload_length,
            source,
            destination,
        };
        ticket.validate()?;
        Ok(ticket)
    }

    pub fn from_json(data: &[u8]) -> Result<Self, Error> {
        let wire: TransitionTicketWire = serde_json::from_slice(data)
            .map_err(|error| Error::InvalidTicket(format!("invalid JSON: {error}")))?;
        if wire.schema != TRANSITION_TICKET_SCHEMA {
            return Err(Error::InvalidTicket("invalid schema".into()));
        }
        if wire.version != TRANSITION_TICKET_VERSION {
            return Err(Error::InvalidTicket("unsupported version".into()));
        }
        let queue_id = steadq_names::hex_decode_16(&wire.queue_id)
            .ok_or_else(|| Error::InvalidTicket("invalid queue_id".into()))?;
        let job_id = steadq_names::hex_decode_16(&wire.source_identity.job_id)
            .ok_or_else(|| Error::InvalidTicket("invalid job_id".into()))?;
        let lease_token = steadq_names::hex_decode_16(&wire.source_identity.lease_token)
            .ok_or_else(|| Error::InvalidTicket("invalid lease_token".into()))?;
        let envelope_digest = steadq_names::hex_decode_32(&wire.source_identity.envelope_digest)
            .ok_or_else(|| Error::InvalidTicket("invalid envelope_digest".into()))?;
        Self::new(
            queue_id,
            wire.operation,
            wire.phase,
            TicketIdentity::new(
                job_id,
                wire.source_identity.generation,
                wire.source_identity.attempt,
                wire.source_identity.maximum_attempts,
                lease_token,
                TicketEvidence::new(envelope_digest, wire.source_identity.payload_length),
            ),
            wire.source,
            wire.destination_derivation,
        )
    }

    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        let wire = TransitionTicketWire {
            schema: TRANSITION_TICKET_SCHEMA.into(),
            version: TRANSITION_TICKET_VERSION,
            queue_id: steadq_names::hex_encode(&self.queue_id),
            operation: self.operation,
            phase: self.phase,
            source_identity: TicketIdentityWire {
                job_id: steadq_names::hex_encode(&self.job_id),
                generation: self.source_generation,
                attempt: self.source_attempt,
                maximum_attempts: self.maximum_attempts,
                lease_token: steadq_names::hex_encode(&self.lease_token),
                envelope_digest: steadq_names::hex_encode(&self.envelope_digest),
                payload_length: self.payload_length,
            },
            source: self.source.clone(),
            destination_derivation: self.destination.clone(),
        };
        serde_json::to_vec_pretty(&wire)
            .map_err(|error| Error::InvalidTicket(format!("serialization failed: {error}")))
    }

    pub fn operation(&self) -> TransitionOperation {
        self.operation
    }

    pub fn phase(&self) -> TransitionPhase {
        self.phase
    }

    pub fn queue_id(&self) -> [u8; 16] {
        self.queue_id
    }

    pub fn job_id(&self) -> [u8; 16] {
        self.job_id
    }

    pub fn source_generation(&self) -> u64 {
        self.source_generation
    }

    pub fn source_attempt(&self) -> u32 {
        self.source_attempt
    }

    pub fn maximum_attempts(&self) -> u32 {
        self.maximum_attempts
    }

    pub fn lease_token(&self) -> [u8; 16] {
        self.lease_token
    }

    pub fn envelope_digest(&self) -> [u8; 32] {
        self.envelope_digest
    }

    pub fn payload_length(&self) -> u64 {
        self.payload_length
    }

    pub fn source(&self) -> &TicketSource {
        &self.source
    }

    pub fn destination(&self) -> &TicketDestination {
        &self.destination
    }

    pub(crate) fn with_phase(&self, phase: TransitionPhase) -> Self {
        let mut ticket = self.clone();
        ticket.phase = phase;
        ticket
    }

    pub(crate) fn source_common(&self) -> steadq_names::CommonFields {
        steadq_names::CommonFields {
            job_id: self.job_id,
            generation: self.source_generation,
            attempt: self.source_attempt,
            maximum_attempts: self.maximum_attempts,
        }
    }

    pub(crate) fn destination_common(&self) -> Result<steadq_names::CommonFields, Error> {
        let generation = self
            .source_generation
            .checked_add(1)
            .ok_or_else(|| Error::InvalidTicket("source generation cannot increment".into()))?;
        let attempt = if self.operation == TransitionOperation::Claim {
            self.source_attempt
                .checked_add(1)
                .ok_or_else(|| Error::InvalidTicket("source attempt cannot increment".into()))?
        } else {
            self.source_attempt
        };
        Ok(steadq_names::CommonFields {
            job_id: self.job_id,
            generation,
            attempt,
            maximum_attempts: self.maximum_attempts,
        })
    }

    pub(crate) fn validate_for_queue(&self, queue_id: &[u8; 16]) -> Result<(), Error> {
        self.validate()?;
        if &self.queue_id != queue_id {
            return Err(Error::InvalidTicket(
                "ticket belongs to another queue".into(),
            ));
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), Error> {
        if self.maximum_attempts == 0 {
            return Err(Error::InvalidTicket(
                "ticket maximum_attempts must be nonzero".into(),
            ));
        }
        if self.source_attempt > self.maximum_attempts {
            return Err(Error::InvalidTicket(
                "ticket attempt exceeds maximum_attempts".into(),
            ));
        }
        self.destination_common()?;
        let legal = match (&self.operation, &self.source, &self.destination) {
            (
                TransitionOperation::Claim,
                TicketSource::Ready {},
                TicketDestination::Leased { .. },
            ) => self.source_attempt < self.maximum_attempts,
            (
                TransitionOperation::Renew,
                TicketSource::Leased { .. },
                TicketDestination::Leased { .. },
            )
            | (
                TransitionOperation::Acknowledge,
                TicketSource::Leased { .. },
                TicketDestination::Receipt { .. },
            )
            | (
                TransitionOperation::RetryNow,
                TicketSource::Leased { .. },
                TicketDestination::Ready {},
            )
            | (
                TransitionOperation::RetryLater,
                TicketSource::Leased { .. },
                TicketDestination::Delayed { .. },
            )
            | (
                TransitionOperation::Bury,
                TicketSource::Leased { .. },
                TicketDestination::Dead { .. },
            ) => true,
            _ => false,
        };
        if !legal {
            return Err(Error::InvalidTicket(
                "operation does not permit the ticket source and destination".into(),
            ));
        }
        for boot_id in [self.source_boot_id(), self.destination_boot_id()]
            .into_iter()
            .flatten()
        {
            if steadq_names::boot_id_bytes(boot_id).is_none() {
                return Err(Error::InvalidTicket(
                    "ticket boot_id is not canonical".into(),
                ));
            }
        }
        Ok(())
    }

    fn source_boot_id(&self) -> Option<&str> {
        match &self.source {
            TicketSource::Ready {} => None,
            TicketSource::Leased { boot_id, .. } => Some(boot_id),
        }
    }

    fn destination_boot_id(&self) -> Option<&str> {
        match &self.destination {
            TicketDestination::Leased { boot_id, .. } => Some(boot_id),
            _ => None,
        }
    }
}

/// Lease info returned from claim or renew.
#[derive(Debug, Clone)]
pub struct LeaseInfo {
    pub job_id: [u8; 16],
    pub envelope_digest: [u8; 32],
    pub generation: u64,
    pub attempt: u32,
    pub maximum_attempts: u32,
    pub token: [u8; 16],
    pub boot_id: String,
    pub expires_boottime_ns: u64,
    pub expires_wall_ns: u64,
    pub content_type: String,
    pub payload_length: u64,
    pub payload_digest: [u8; 32],
    pub expected_dev: u64,
    pub expected_inode: u64,
    pub exact_source_path: String,
}

impl LeaseInfo {
    /// Remaining lease time in nanoseconds based on CLOCK_BOOTTIME.
    pub fn remaining_ns(&self, current_boottime_ns: u64) -> u64 {
        self.expires_boottime_ns.saturating_sub(current_boottime_ns)
    }
}

/// Dead reason codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum DeadReason {
    Unspecified = 0x0000,
    ConsumerRejected = 0x0001,
    UnsupportedContentType = 0x0002,
    AdministrativeBury = 0x0003,
    AttemptsExhausted = 0x0004,
}

impl DeadReason {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0x0000 => Some(Self::Unspecified),
            0x0001 => Some(Self::ConsumerRejected),
            0x0002 => Some(Self::UnsupportedContentType),
            0x0003 => Some(Self::AdministrativeBury),
            0x0004 => Some(Self::AttemptsExhausted),
            _ => None,
        }
    }
}

/// Quarantine reason codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum QuarantineReason {
    EnvelopeCorrupt = 0x0001,
    PayloadCorrupt = 0x0002,
    FilenameParseFailed = 0x0003,
    FilenameTagFailed = 0x0004,
    FilenameHeaderMismatch = 0x0005,
    UnsupportedRequiredFeature = 0x0006,
    DuplicateStateConflict = 0x0007,
    NonRegularFile = 0x0008,
    UnexpectedHardLink = 0x0009,
    CrossDeviceObject = 0x000a,
    ImpossibleStateTransition = 0x000b,
}

impl QuarantineReason {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0x0001 => Some(Self::EnvelopeCorrupt),
            0x0002 => Some(Self::PayloadCorrupt),
            0x0003 => Some(Self::FilenameParseFailed),
            0x0004 => Some(Self::FilenameTagFailed),
            0x0005 => Some(Self::FilenameHeaderMismatch),
            0x0006 => Some(Self::UnsupportedRequiredFeature),
            0x0007 => Some(Self::DuplicateStateConflict),
            0x0008 => Some(Self::NonRegularFile),
            0x0009 => Some(Self::UnexpectedHardLink),
            0x000a => Some(Self::CrossDeviceObject),
            0x000b => Some(Self::ImpossibleStateTransition),
            _ => None,
        }
    }
}

/// Resolution outcome from resolve().
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolutionOutcome {
    DestinationObserved,
    DestinationStabilized,
    SourceObserved,
    SourceStabilized,
    BothObserved,
    NeitherObserved,
    ConflictingObject,
    ResolutionFailed(Error),
}

/// Diagnostic snapshot of a job's current state.
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub job_id: [u8; 16],
    pub state: String,
    pub generation: u64,
    pub attempt: u32,
    pub maximum_attempts: u32,
    pub shard: u32,
    pub relative_path: String,
    pub size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dead_reason_round_trip() {
        for code in [0x0000u16, 0x0001, 0x0002, 0x0003, 0x0004] {
            let reason = DeadReason::from_u16(code).unwrap();
            assert_eq!(reason as u16, code);
        }
        assert!(DeadReason::from_u16(0x0005).is_none());
    }

    #[test]
    fn quarantine_reason_round_trip() {
        for code in 0x0001u16..=0x000b {
            let reason = QuarantineReason::from_u16(code).unwrap();
            assert_eq!(reason as u16, code);
        }
        assert!(QuarantineReason::from_u16(0x000c).is_none());
    }

    #[test]
    fn lease_remaining() {
        let lease = LeaseInfo {
            job_id: [0; 16],
            envelope_digest: [0; 32],
            generation: 0,
            attempt: 0,
            maximum_attempts: 1,
            token: [0; 16],
            boot_id: "00000000-0000-0000-0000-000000000000".to_string(),
            expires_boottime_ns: 10_000_000_000,
            expires_wall_ns: 0,
            content_type: "x".to_string(),
            payload_length: 0,
            payload_digest: [0; 32],
            expected_dev: 0,
            expected_inode: 0,
            exact_source_path: "ready/0000/x.sqj".to_string(),
        };
        assert_eq!(lease.remaining_ns(5_000_000_000), 5_000_000_000);
        assert_eq!(lease.remaining_ns(10_000_000_000), 0);
        assert_eq!(lease.remaining_ns(15_000_000_000), 0);
    }

    fn valid_transition_ticket() -> TransitionTicket {
        TransitionTicket::new(
            [5; 16],
            TransitionOperation::Claim,
            TransitionPhase::Linearized,
            TicketIdentity::new([6; 16], 7, 2, 4, [8; 16], TicketEvidence::new([9; 32], 12)),
            TicketSource::Ready {},
            TicketDestination::Leased {
                boot_id: "00000000-0000-0000-0000-000000000000".into(),
                boottime_deadline_ns: 10,
                wall_deadline_ns: 11,
            },
        )
        .unwrap()
    }

    #[test]
    fn transition_ticket_json_round_trip() {
        let ticket = valid_transition_ticket();
        let encoded = ticket.to_json().unwrap();
        let decoded = TransitionTicket::from_json(&encoded).unwrap();
        assert_eq!(decoded, ticket);
        let value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(value["schema"], TRANSITION_TICKET_SCHEMA);
        assert_eq!(value["version"], TRANSITION_TICKET_VERSION);
        assert!(value.get("source_relative_path").is_none());
        assert!(value.get("attempted_destination_relative_path").is_none());
    }

    #[test]
    fn transition_ticket_accessors_preserve_identity() {
        let ticket = valid_transition_ticket();
        assert_eq!(ticket.queue_id(), [5; 16]);
        assert_eq!(ticket.operation(), TransitionOperation::Claim);
        assert_eq!(ticket.phase(), TransitionPhase::Linearized);
        assert_eq!(ticket.job_id(), [6; 16]);
        assert_eq!(ticket.source_generation(), 7);
        assert_eq!(ticket.source_attempt(), 2);
        assert_eq!(ticket.maximum_attempts(), 4);
        assert_eq!(ticket.lease_token(), [8; 16]);
        assert_eq!(ticket.envelope_digest(), [9; 32]);
        assert_eq!(ticket.payload_length(), 12);
        assert!(matches!(ticket.source(), TicketSource::Ready {}));
        assert!(matches!(
            ticket.destination(),
            TicketDestination::Leased {
                boottime_deadline_ns: 10,
                wall_deadline_ns: 11,
                ..
            }
        ));
    }

    #[test]
    fn transition_ticket_json_rejects_unknown_fields_and_wrong_schema() {
        let ticket = valid_transition_ticket();
        let mut value: serde_json::Value =
            serde_json::from_slice(&ticket.to_json().unwrap()).unwrap();
        value["unexpected"] = serde_json::json!(true);
        assert!(TransitionTicket::from_json(&serde_json::to_vec(&value).unwrap()).is_err());

        value.as_object_mut().unwrap().remove("unexpected");
        value["source"]["relative_path"] = serde_json::json!("../../outside");
        assert!(TransitionTicket::from_json(&serde_json::to_vec(&value).unwrap()).is_err());

        value["source"]
            .as_object_mut()
            .unwrap()
            .remove("relative_path");
        value["schema"] = serde_json::json!("another-schema");
        assert!(TransitionTicket::from_json(&serde_json::to_vec(&value).unwrap()).is_err());

        value["schema"] = serde_json::json!(TRANSITION_TICKET_SCHEMA);
        value["version"] = serde_json::json!(TRANSITION_TICKET_VERSION + 1);
        assert!(TransitionTicket::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn transition_ticket_rejects_operation_identity_mismatches() {
        let mut ticket = valid_transition_ticket();
        ticket.destination = TicketDestination::Receipt { terminal_bucket: 0 };
        assert!(ticket.validate().is_err());

        ticket = valid_transition_ticket();
        ticket.maximum_attempts = 0;
        assert!(ticket.validate().is_err());

        ticket = valid_transition_ticket();
        ticket.source_attempt = ticket.maximum_attempts;
        assert!(ticket.validate().is_err());

        ticket = valid_transition_ticket();
        ticket.source_generation = u64::MAX;
        assert!(matches!(ticket.validate(), Err(Error::InvalidTicket(_))));

        ticket = valid_transition_ticket();
        ticket.source = TicketSource::Leased {
            boot_id: "not-a-boot-id".into(),
            boottime_deadline_ns: 1,
            wall_deadline_ns: 2,
        };
        ticket.operation = TransitionOperation::Renew;
        assert!(ticket.validate().is_err());

        ticket = valid_transition_ticket();
        ticket.destination = TicketDestination::Leased {
            boot_id: "not-a-boot-id".into(),
            boottime_deadline_ns: 1,
            wall_deadline_ns: 2,
        };
        assert!(ticket.validate().is_err());
    }

    #[test]
    fn transition_ticket_operation_matrix() {
        let boot_id = "00000000-0000-0000-0000-000000000000".to_string();
        let leased_source = || TicketSource::Leased {
            boot_id: boot_id.clone(),
            boottime_deadline_ns: 10,
            wall_deadline_ns: 20,
        };
        let cases = [
            (
                TransitionOperation::Claim,
                TicketSource::Ready {},
                TicketDestination::Leased {
                    boot_id: boot_id.clone(),
                    boottime_deadline_ns: 30,
                    wall_deadline_ns: 40,
                },
            ),
            (
                TransitionOperation::Renew,
                leased_source(),
                TicketDestination::Leased {
                    boot_id: boot_id.clone(),
                    boottime_deadline_ns: 30,
                    wall_deadline_ns: 40,
                },
            ),
            (
                TransitionOperation::Acknowledge,
                leased_source(),
                TicketDestination::Receipt { terminal_bucket: 5 },
            ),
            (
                TransitionOperation::RetryNow,
                leased_source(),
                TicketDestination::Ready {},
            ),
            (
                TransitionOperation::RetryLater,
                leased_source(),
                TicketDestination::Delayed { not_before_ns: 50 },
            ),
            (
                TransitionOperation::Bury,
                leased_source(),
                TicketDestination::Dead {
                    terminal_bucket: 5,
                    reason: 3,
                },
            ),
        ];

        for (operation, source, destination) in cases {
            assert!(TransitionTicket::new(
                [1; 16],
                operation,
                TransitionPhase::Linearized,
                TicketIdentity::new([2; 16], 7, 1, 3, [3; 16], TicketEvidence::new([4; 32], 5),),
                source,
                destination,
            )
            .is_ok());
        }

        let invalid_destinations = [
            TicketDestination::Ready {},
            TicketDestination::Delayed { not_before_ns: 50 },
            TicketDestination::Receipt { terminal_bucket: 5 },
            TicketDestination::Dead {
                terminal_bucket: 5,
                reason: 3,
            },
        ];
        for destination in invalid_destinations {
            assert!(TransitionTicket::new(
                [1; 16],
                TransitionOperation::Renew,
                TransitionPhase::Linearized,
                TicketIdentity::new([2; 16], 7, 1, 3, [3; 16], TicketEvidence::new([4; 32], 5),),
                leased_source(),
                destination,
            )
            .is_err());
        }
    }
}
