//! Who delivers a message: the two contracts the relay dispatches to, and the registry of them.
//!
//! - [`OutboxHandler`] delivers a message that is not a scan notification (the SIEM export, the agents' audit
//!   entries…), handed the payload **as stored**: each handler reads its own shape.
//! - [`NotificationChannel`] is one destination of a scan's delta (the webhook, Teams, Slack, Discord, mail), one row
//!   per destination so that a retry reaches the one that failed and only it.
//!
//! Both are declared here, beside the relay, and implemented by the modules that own the destinations: kept with them,
//! the outbox would depend on the domains that enqueue into it (decision 0026).

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde::Deserialize;
use uuid::Uuid;

/// A delivery under way.
pub type Delivery<'a> = Pin<Box<dyn Future<Output = Result<(), DeliveryError>> + Send + 'a>>;

/// Why a delivery did not happen. A destination **returns** its failure, never swallows it: the relay is what turns
/// it into "retry later", and a swallowed failure is one never retried.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeliveryError {
    /// The destination no longer exists — Java's `GoneDestinationException`. Abandoned at once, not retried for four
    /// hours: nothing about waiting brings back a team somebody deleted. `last_error` keeps the reason **whole and
    /// as written**, without the `Kind: ` prefix or the 500-unit cut of a failure — Java's `abandon` stores
    /// `getMessage()` as it is.
    #[error("{0}")]
    Gone(String),
    /// Anything else: retried on the backoff, then abandoned. `kind` is the simple name of the exception the Java
    /// sender of the same destination throws (`OutboundFailureException`…), so that `last_error` reads the same
    /// whichever control plane wrote it; `message` is its message, `None` where Java's is `null`.
    #[error("{kind}: {}", message.as_deref().unwrap_or("null"))]
    Failed { kind: String, message: Option<String> },
}

impl DeliveryError {
    pub fn failed(kind: impl Into<String>, message: impl Into<String>) -> DeliveryError {
        DeliveryError::Failed { kind: kind.into(), message: Some(message.into()) }
    }
}

/// Delivers an outbox message that is not a scan notification.
pub trait OutboxHandler: Send + Sync {
    /// The `message_type` it delivers. Stored on every row, so it must not move.
    fn message_type(&self) -> &str;

    /// `message_id` is the row's id, also stamped into the payload: what a receiver deduplicates on. `payload` is the
    /// JSON that was queued, exactly as stored.
    fn deliver<'a>(&'a self, message_id: Uuid, payload: &'a str) -> Delivery<'a>;
}

/// One destination a scan's delta can reach.
///
/// **Handed the stored text, not a parsed `NotificationPayload`** — a difference from Java, whose relay parses the
/// payload before calling the channel. The payload's shape is the notifications module's (Phase 4), not the relay's;
/// the channel reads it. What changes is only the wording of `last_error` for a payload that does not parse: Jackson's
/// sentence in Java, the channel's here. Both retry and then abandon it.
pub trait NotificationChannel: Send + Sync {
    /// The `message_type` that routes to this channel. Stored, so it must not move.
    fn message_type(&self) -> &str;

    /// Whether this deployment has somewhere to send. An unconfigured channel is queued nothing (by the enqueuer).
    fn is_configured(&self) -> bool;

    /// `team_id` is whose channel this copy is for, `None` for the global destination. Only the generic webhook has
    /// per-team destinations; the others ignore it, as Java's default method does.
    fn deliver<'a>(&'a self, payload: &'a str, team_id: Option<i64>) -> Delivery<'a>;
}

/// Where a row goes.
pub(crate) enum Route<'a> {
    Handler(&'a dyn OutboxHandler),
    Channel(&'a dyn NotificationChannel),
}

/// Every handler and channel this binary has.
#[derive(Clone, Default)]
pub struct Registry {
    handlers: Vec<Arc<dyn OutboxHandler>>,
    channels: Vec<Arc<dyn NotificationChannel>>,
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry")
            .field("handlers", &self.handler_types())
            .field("channels", &self.channel_types())
            .finish()
    }
}

impl Registry {
    pub fn new(handlers: Vec<Arc<dyn OutboxHandler>>, channels: Vec<Arc<dyn NotificationChannel>>) -> Registry {
        Registry { handlers, channels }
    }

    /// Java's `deliver`: a handler first, then a channel, the first registered of either that names the type.
    pub(crate) fn route(&self, message_type: &str) -> Option<Route<'_>> {
        if let Some(handler) = self.handlers.iter().find(|handler| handler.message_type() == message_type) {
            return Some(Route::Handler(handler.as_ref()));
        }
        self.channels
            .iter()
            .find(|channel| channel.message_type() == message_type)
            .map(|channel| Route::Channel(channel.as_ref()))
    }

    pub fn handler_types(&self) -> BTreeSet<String> {
        self.handlers.iter().map(|handler| handler.message_type().to_owned()).collect()
    }

    pub fn channel_types(&self) -> BTreeSet<String> {
        self.channels.iter().map(|channel| channel.message_type().to_owned()).collect()
    }

    /// How this registry differs from the one the Java control plane relays with.
    pub fn coverage(&self, java: &JavaRegistry) -> Coverage {
        let difference = |ours: &BTreeSet<String>, theirs: &BTreeSet<String>| -> Vec<String> {
            theirs.difference(ours).cloned().collect()
        };
        let (handlers, channels) = (self.handler_types(), self.channel_types());
        Coverage {
            missing_handlers: difference(&handlers, &java.handlers),
            missing_channels: difference(&channels, &java.channels),
            extra_handlers: difference(&java.handlers, &handlers),
            extra_channels: difference(&java.channels, &channels),
        }
    }
}

/// The types the started Java application relays, as `OutboxRegistryReferenceSetTest` reads them from its beans —
/// `reference/outbox/registry.json`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct JavaRegistry {
    pub handlers: BTreeSet<String>,
    pub channels: BTreeSet<String>,
}

/// The Java registry this binary is held to. Compiled in rather than read at start: the comparison is a property of
/// the build, which the Java side regenerates on purpose when it adds a type, and a file looked up at run time could
/// be missing in exactly the deployment that needed it.
pub const JAVA_REGISTRY: &str = include_str!("../../../reference/outbox/registry.json");

impl JavaRegistry {
    /// [`JAVA_REGISTRY`], read.
    pub fn compiled_in() -> Result<JavaRegistry, serde_json::Error> {
        serde_json::from_str(JAVA_REGISTRY)
    }
}

/// What a registry lacks, or has too much of, against Java's.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Coverage {
    /// Types Java relays and this binary does not: their rows would be retried and then abandoned.
    pub missing_handlers: Vec<String>,
    pub missing_channels: Vec<String>,
    /// Types this binary relays and Java does not: their rows would be abandoned by Java after a switch back.
    pub extra_handlers: Vec<String>,
    pub extra_channels: Vec<String>,
}

impl Coverage {
    pub fn is_complete(&self) -> bool {
        self.missing_handlers.is_empty()
            && self.missing_channels.is_empty()
            && self.extra_handlers.is_empty()
            && self.extra_channels.is_empty()
    }
}

impl std::fmt::Display for Coverage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "handlers missing {:?}, channels missing {:?}, handlers Java lacks {:?}, channels Java lacks {:?}",
            self.missing_handlers, self.missing_channels, self.extra_handlers, self.extra_channels
        )
    }
}
