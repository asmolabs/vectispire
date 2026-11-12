//! What a writer hands the audit log, and what the log hands back — `AuditLogService.Record`, `RequestActor`,
//! the row as `AuditEntryView` reads it, the clock.

use time::OffsetDateTime;
use uuid::Uuid;

use crate::operation::AuditOperation;

/// The security event an entry stands for, by its wire name (`SecurityEventType`), when its writer says so.
///
/// Not stored — the column set, and so the hash chain, is unchanged. The SIEM module owns the vocabulary; until
/// it is ported this is the name it will read, carried through to the listeners untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signal(pub &'static str);

/// An entry to append.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub operation: AuditOperation,
    /// Absent is stored as the four letters `null`, as `String.valueOf` writes it — but the listeners get the
    /// caller's absence, not the letters, which a SOC would read as a name.
    pub resource_id: Option<String>,
    /// The column is `not null`: an absent description is refused by the database, and [`crate::AuditLog::record`]
    /// logs that, as Java's does.
    pub description: Option<String>,
    /// The username, not the numeric id: an entry must stay readable after the account is deleted.
    pub user_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    /// `None` leaves it to the SIEM's `signalledBy`, which answers only for operations that are unambiguous.
    pub signal: Option<Signal>,
}

impl Record {
    /// `Record.of`: no address and no user agent.
    pub fn of(operation: AuditOperation, resource_id: &str, description: &str, user_id: Option<&str>) -> Record {
        Record {
            operation,
            resource_id: Some(resource_id.to_owned()),
            description: Some(description.to_owned()),
            user_id: user_id.map(str::to_owned),
            ip_address: None,
            user_agent: None,
            signal: None,
        }
    }

    /// The same entry, naming the security event it stands for — for the operations too broad to signal on
    /// their own (`LOGIN_BLOCKED` is the throttle and also "password sign-in is off").
    pub fn signalling(self, signal: Signal) -> Record {
        Record { signal: Some(signal), ..self }
    }
}

/// Who did something, and from where (`RequestActor`): identity only, one type where Java once had nine.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RequestActor {
    /// The name the entry is attributed to, already resolved by the route — each keeps the fallback it has
    /// always written, because changing it would rewrite how past and future entries compare.
    pub username: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

impl RequestActor {
    /// An entry attributed to this actor.
    pub fn entry(&self, operation: AuditOperation, resource_id: &str, description: &str) -> Record {
        Record {
            operation,
            resource_id: Some(resource_id.to_owned()),
            description: Some(description.to_owned()),
            user_id: self.username.clone(),
            ip_address: self.ip_address.clone(),
            user_agent: self.user_agent.clone(),
            signal: None,
        }
    }
}

/// A row of `t_audit_log`, as the screen and the verification read it (`AuditEntryView`): the hashes
/// included, since they are what lets a reader check the chain themselves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEntry {
    pub id: Uuid,
    pub description: String,
    pub operation_type: String,
    pub resource_id: String,
    pub timestamp: OffsetDateTime,
    pub user_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub previous_hash: Option<String>,
    pub entry_hash: Option<String>,
}

impl StoredEntry {
    pub(crate) fn from_row(row: crate::persistence::Row) -> StoredEntry {
        let crate::persistence::Row {
            id,
            description,
            operation_type,
            resource_id,
            timestamp,
            user_id,
            ip_address,
            user_agent,
            previous_hash,
            entry_hash,
        } = row;
        StoredEntry {
            id,
            description,
            operation_type,
            resource_id,
            timestamp,
            user_id,
            ip_address,
            user_agent,
            previous_hash,
            entry_hash,
        }
    }

    pub(crate) fn to_row(&self) -> crate::persistence::Row {
        crate::persistence::Row {
            id: self.id,
            description: self.description.clone(),
            operation_type: self.operation_type.clone(),
            resource_id: self.resource_id.clone(),
            timestamp: self.timestamp,
            user_id: self.user_id.clone(),
            ip_address: self.ip_address.clone(),
            user_agent: self.user_agent.clone(),
            previous_hash: self.previous_hash.clone(),
            entry_hash: self.entry_hash.clone(),
        }
    }

    /// The fields that go into its hash.
    pub fn chain_entry(&self) -> crate::chain::Entry {
        crate::chain::Entry {
            previous_hash: self.previous_hash.clone(),
            timestamp: Some(self.timestamp),
            operation_type: Some(self.operation_type.clone()),
            resource_id: Some(self.resource_id.clone()),
            user_id: self.user_id.clone(),
            ip_address: self.ip_address.clone(),
            user_agent: self.user_agent.clone(),
            description: Some(self.description.clone()),
        }
    }

    /// As the verification reads it.
    pub fn verifiable(&self) -> crate::chain::VerifiableEntry {
        crate::chain::VerifiableEntry {
            id: self.id.as_hyphenated().to_string(),
            entry_hash: self.entry_hash.clone(),
            entry: self.chain_entry(),
        }
    }
}

/// Where an entry's instant comes from (`java.time.Clock`).
pub trait Clock: Send + Sync + std::fmt::Debug {
    fn now(&self) -> OffsetDateTime;
}

/// The system's clock, in UTC.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}
