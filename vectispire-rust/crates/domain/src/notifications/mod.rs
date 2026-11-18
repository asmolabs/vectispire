//! What a scan's delta and an integration token's change of state say, and how each chat renders it —
//! `common.domain.notifications`, ported.
//!
//! **Pure**: no channel, no clock, no setting. The `notifications` module (`cp-notifications`) reads the destinations
//! and sends; the owners of a token (`tickets`, `forges`) build a [`TokenAlert`] here and hand it to the channels
//! through a port, so neither depends on the other — the arrangement Java keeps by publishing the alert as an
//! application event declared in this package.
//!
//! The JSON a chat receives is built as an ordered `serde_json::Value` (the workspace turns on `preserve_order`),
//! in the order Java inserts the members. Where Java builds a member with `Map.of` its order is salted per JVM run,
//! so no receiver can depend on it; the order here is the source's.

pub mod chat_text;
pub mod kind;
pub mod mail;
pub mod payload;
pub mod renderers;
pub mod selection;
pub mod signature;
pub mod token_alert;
pub mod token_alert_messages;

pub use kind::NotificationChannelKind;
pub use mail::MailContent;
pub use payload::{Delta, Detail, NotifiableIssue, NotificationPayload};
pub use token_alert::{Credential, Notice, TokenAlert};

/// `publicUrl.replaceAll("/+$", "")`: every trailing slash off.
pub(crate) fn without_trailing_slashes(url: &str) -> &str {
    url.trim_end_matches('/')
}

/// A public URL a message may link to: present and not blank.
pub(crate) fn public_base(public_url: Option<&str>) -> Option<&str> {
    public_url.filter(|url| !crate::java::is_blank(url)).map(without_trailing_slashes)
}
