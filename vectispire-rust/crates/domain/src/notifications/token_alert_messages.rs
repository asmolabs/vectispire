//! `TokenAlertMessages`: a [`TokenAlert`] as each channel takes it. Not the scan delta's shapes — an alert about a
//! token has no target, scan or counts, and bent into them it would be a message with `scan_id: 0` a receiver reads
//! as a scan. The generic webhook carries `event: "token_state_changed"` instead.

use serde_json::{Map, Value, json};

use super::chat_text;
use super::mail::MailContent;
use super::public_base;
use super::renderers::{CARD_SCHEMA, teams_envelope, text_block};
use super::token_alert::{Notice, TokenAlert, one_line};
use crate::instant::Instant;

/// Told apart from a scan delta by this member, which a scan delta never carries.
pub const EVENT: &str = "token_state_changed";
/// Past this many characters Slack refuses the whole message.
const SLACK_HEADER: usize = 150;

fn instant(value: Option<Instant>) -> Value {
    value.and_then(Instant::to_java_string).map_or(Value::Null, Value::String)
}

fn link(alert: &TokenAlert, public_url: Option<&str>) -> Option<String> {
    public_base(public_url).map(|base| format!("{base}{}", alert.credential.screen()))
}

/// The generic webhook's body: the sentence first as `text`, then the facts a receiver's rules can test.
pub fn webhook(alert: &TokenAlert, message_id: &str) -> Value {
    let mut body = Map::new();
    body.insert("text".into(), alert.sentence().into());
    body.insert("event".into(), EVENT.into());
    body.insert("credential".into(), alert.credential.wire_name().into());
    body.insert("name".into(), one_line(alert.name.as_deref()).into());
    body.insert("reference".into(), alert.reference.clone().map_or(Value::Null, Value::String));
    body.insert("state".into(), alert.notice.wire_name().into());
    body.insert("previous_state".into(), alert.previous.wire_name().into());
    body.insert("signature_id".into(), alert.signal().signature_id().into());
    body.insert("expires_at".into(), instant(alert.expires_at));
    body.insert("refused_status".into(), alert.refused_status.map_or(Value::Null, Value::from));
    body.insert("refused_since".into(), instant(alert.refused_since));
    body.insert("observed_at".into(), instant(alert.observed_at));
    body.insert("message_id".into(), message_id.into());
    Value::Object(body)
}

/// Slack: the header without the connection's name (plain text has no escape), cut within 150 UTF-16 units.
pub fn slack(alert: &TokenAlert, public_url: Option<&str>) -> Value {
    let headline = alert.anonymous_headline();
    let units: Vec<u16> = headline.encode_utf16().collect();
    let header = if units.len() <= SLACK_HEADER {
        headline
    } else {
        format!("{}…", crate::java::from_utf16(units.get(..SLACK_HEADER.saturating_sub(1)).unwrap_or_default()))
    };
    let mut blocks = vec![
        json!({"type": "header", "text": {"type": "plain_text", "text": header, "emoji": true}}),
        json!({"type": "section", "text": {"type": "mrkdwn", "text": chat_text::slack(&alert.sentence())}}),
    ];
    if let Some(url) = link(alert, public_url) {
        blocks.push(json!({"type": "actions", "elements": [{
            "type": "button",
            "text": {"type": "plain_text", "text": "Open in Vectispire", "emoji": true},
            "url": url,
        }]}));
    }
    json!({"text": chat_text::slack(&alert.sentence()), "blocks": blocks})
}

/// An Adaptive Card in the workflow's envelope.
pub fn teams(alert: &TokenAlert, public_url: Option<&str>) -> Value {
    let colour = if alert.notice.stopped() {
        "attention"
    } else if alert.notice == Notice::ExpiresSoon {
        "warning"
    } else {
        "good"
    };
    let body = vec![
        text_block(&chat_text::teams(&alert.headline()), "bolder", "medium", colour, None),
        text_block(&chat_text::teams(&alert.sentence()), "default", "default", "default", None),
    ];
    let mut card = Map::new();
    card.insert("type".into(), "AdaptiveCard".into());
    card.insert("$schema".into(), CARD_SCHEMA.into());
    card.insert("version".into(), "1.4".into());
    card.insert("body".into(), body.into());
    if let Some(url) = link(alert, public_url) {
        card.insert("actions".into(), json!([{"type": "Action.OpenUrl", "title": "Open in Vectispire", "url": url}]));
    }
    teams_envelope(Value::Object(card))
}

/// One embed; nothing it says may ping anybody.
pub fn discord(alert: &TokenAlert, public_url: Option<&str>) -> Value {
    let color = if alert.notice.stopped() {
        0x00DC_2626
    } else if alert.notice == Notice::ExpiresSoon {
        0x00D9_7706
    } else {
        0x0005_9669
    };
    let mut embed = Map::new();
    embed.insert("title".into(), chat_text::discord(&alert.headline()).into());
    embed.insert("description".into(), chat_text::discord(&alert.sentence()).into());
    embed.insert("color".into(), color.into());
    embed.insert("timestamp".into(), instant(alert.observed_at));
    if let Some(url) = link(alert, public_url) {
        embed.insert("url".into(), url.into());
    }
    embed.insert("footer".into(), json!({"text": "Vectispire DevSecOps Platform"}));
    json!({"username": "Vectispire Security", "embeds": [Value::Object(embed)], "allowed_mentions": {"parse": []}})
}

/// Plain text; the subject is the headline, on one line.
pub fn mail(alert: &TokenAlert, public_url: Option<&str>, message_id: &str) -> MailContent {
    let java = |value: Option<Instant>| value.and_then(Instant::to_java_string).unwrap_or_else(|| "null".to_owned());
    let mut lines = vec![
        alert.sentence(),
        String::new(),
        format!("State:     {} (was {})", alert.notice.wire_name(), alert.previous.wire_name()),
    ];
    if alert.expires_at.is_some() {
        lines.push(format!("Expiry:    {}", java(alert.expires_at)));
    }
    if let Some(status) = alert.refused_status {
        lines.push(format!("Refused:   HTTP {status} since {}", java(alert.refused_since)));
    }
    lines.push(format!("Noticed:   {}", java(alert.observed_at)));
    if let Some(url) = link(alert, public_url) {
        lines.push(String::new());
        lines.push(url);
    }
    lines.push(String::new());
    lines.push(format!("Message {message_id}"));
    MailContent { subject: alert.headline(), body: lines.join("\n") }
}
