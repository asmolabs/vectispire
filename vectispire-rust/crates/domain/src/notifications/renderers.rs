//! A scan's delta as Slack (`SlackBlockKit`), Discord (`DiscordEmbed`) and Microsoft Teams (`TeamsCard`) take it.
//!
//! Every value the message did not write itself goes through [`super::chat_text`] for the chat it is posted to.

use serde_json::{Value, json};

use super::chat_text;
use super::payload::{Detail, NotificationPayload};
use super::public_base;
use crate::instant::Instant;

/// Named in the attachment, and the only value Teams accepts for an adaptive card.
pub(crate) const ADAPTIVE_CARD: &str = "application/vnd.microsoft.card.adaptive";
pub(crate) const CARD_SCHEMA: &str = "http://adaptivecards.io/schemas/adaptive-card.json";

fn text_of(payload: &NotificationPayload) -> &str {
    payload.text.as_deref().unwrap_or("null")
}

fn target_of(payload: &NotificationPayload) -> &str {
    payload.target.as_deref().unwrap_or("null")
}

/// The identifier, or the finding type where there is none — `"null"` where Java would concatenate a null.
fn subject_of(issue: &Detail) -> &str {
    issue.identifier.as_deref().or(issue.kind.as_deref()).unwrap_or("null")
}

/// `SlackBlockKit.of`: Block Kit, with a button back to the backlog when the deployment knows its address.
pub fn slack(payload: &NotificationPayload, public_url: Option<&str>) -> Value {
    let mut blocks = vec![
        json!({"type": "header", "text": {"type": "plain_text", "text": "🛡️ Vectispire Security Alert", "emoji": true}}),
        json!({"type": "section", "text": {"type": "mrkdwn", "text": format!(
            "*Target:* `{}` (Scan #{})\n*{}*",
            chat_text::slack(target_of(payload)),
            payload.scan_id,
            chat_text::slack(text_of(payload))
        )}}),
    ];
    let mut fields = vec![
        json!({"type": "mrkdwn", "text": format!("*New:* {}", payload.new_count)}),
        json!({"type": "mrkdwn", "text": format!("*Reopened:* {}", payload.reopened_count)}),
        json!({"type": "mrkdwn", "text": format!("*Resolved:* {}", payload.resolved_count)}),
    ];
    if payload.kev_count > 0 {
        fields.push(json!({"type": "mrkdwn", "text": format!("*🚨 CISA KEV:* {}", payload.kev_count)}));
    }
    blocks.push(json!({"type": "section", "fields": fields}));
    blocks.push(json!({"type": "divider"}));

    let mut issues = String::from("*Vulnerabilities & Findings:*\n");
    for issue in &payload.issues {
        let emoji = match issue.severity.as_deref().map(crate::java::to_lower_root).as_deref() {
            Some("critical") => "🔴",
            Some("high") => "🟠",
            Some("medium") => "🟡",
            _ => "⚪",
        };
        let cve = chat_text::slack(subject_of(issue));
        let pkg =
            issue.package_name.as_deref().map(|name| format!(" in `{}`", chat_text::slack(name))).unwrap_or_default();
        let fix =
            issue.fix_versions.as_deref().map(|fix| format!(" (fix: {})", chat_text::slack(fix))).unwrap_or_default();
        let kev = if issue.is_kev { " `[CISA KEV]`" } else { "" };
        issues.push_str(&format!("{emoji} *{cve}*{pkg}{fix}{kev}\n"));
    }
    if payload.truncated > 0 {
        issues.push_str(&format!("_...and {} more findings_\n", payload.truncated));
    }
    blocks.push(json!({"type": "section", "text": {"type": "mrkdwn", "text": issues}}));

    if let Some(base) = public_base(public_url) {
        blocks.push(json!({"type": "actions", "elements": [{
            "type": "button",
            "text": {"type": "plain_text", "text": "View in Vectispire", "emoji": true},
            "url": format!("{base}/issues"),
            "style": "primary",
        }]}));
    }

    // The notification's fallback text is read as mrkdwn too.
    json!({"text": chat_text::slack(text_of(payload)), "blocks": blocks})
}

/// `DiscordEmbed.of`: one rich embed; nothing it says may ping anybody. `at` is the embed's timestamp, by the
/// sender's clock.
pub fn discord(payload: &NotificationPayload, public_url: Option<&str>, at: Instant) -> Value {
    let critical = payload
        .issues
        .iter()
        .any(|issue| issue.severity.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("critical")));
    let color = if payload.kev_count > 0 || critical {
        0x00DC_2626
    } else if payload.new_count > 0 || payload.reopened_count > 0 {
        0x00D9_7706
    } else {
        0x0005_9669
    };

    let mut embed = serde_json::Map::new();
    embed.insert(
        "title".into(),
        format!("🛡️ Vectispire: {} (Scan #{})", chat_text::discord(target_of(payload)), payload.scan_id).into(),
    );
    embed.insert("description".into(), chat_text::discord(text_of(payload)).into());
    embed.insert("color".into(), color.into());
    embed.insert("timestamp".into(), at.to_java_string().into());
    if let Some(base) = public_base(public_url) {
        embed.insert("url".into(), format!("{base}/issues").into());
    }

    let mut fields = vec![
        json!({"name": "New Issues", "value": payload.new_count.to_string(), "inline": true}),
        json!({"name": "Reopened", "value": payload.reopened_count.to_string(), "inline": true}),
        json!({"name": "Resolved", "value": payload.resolved_count.to_string(), "inline": true}),
    ];
    if payload.kev_count > 0 {
        fields.push(json!({"name": "🚨 CISA KEV Exploited", "value": payload.kev_count.to_string(), "inline": true}));
    }
    if !payload.issues.is_empty() {
        let mut top = String::new();
        for issue in &payload.issues {
            let cve = chat_text::discord(subject_of(issue));
            let pkg = issue
                .package_name
                .as_deref()
                .map(|name| format!(" ({})", chat_text::discord(name)))
                .unwrap_or_default();
            let fix = issue
                .fix_versions
                .as_deref()
                .map(|fix| format!(" → fix: {}", chat_text::discord(fix)))
                .unwrap_or_default();
            let severity = issue.severity.as_deref().map_or_else(|| "FINDING".to_owned(), crate::java::to_upper_root);
            top.push_str(&format!("• **[{severity}]** {cve}{pkg}{fix}\n"));
        }
        if payload.truncated > 0 {
            top.push_str(&format!("_...and {} more findings_\n", payload.truncated));
        }
        fields.push(json!({"name": "Top Findings", "value": top, "inline": false}));
    }
    embed.insert("fields".into(), fields.into());
    embed.insert("footer".into(), json!({"text": "Vectispire DevSecOps Platform"}));

    json!({"username": "Vectispire Security", "embeds": [Value::Object(embed)], "allowed_mentions": {"parse": []}})
}

/// The colours Teams knows: severity in the four names the client understands.
fn colour_of(severity: Option<&str>) -> &'static str {
    match severity.map(crate::java::to_lower_root).as_deref() {
        Some("critical" | "high") => "attention",
        Some("medium") => "warning",
        _ => "default",
    }
}

pub(crate) fn text_block(value: &str, weight: &str, size: &str, colour: &str, subtle: Option<bool>) -> Value {
    let mut block = serde_json::Map::new();
    block.insert("type".into(), "TextBlock".into());
    block.insert("text".into(), value.into());
    block.insert("weight".into(), weight.into());
    block.insert("size".into(), size.into());
    block.insert("color".into(), colour.into());
    if let Some(subtle) = subtle {
        block.insert("isSubtle".into(), subtle.into());
    }
    // Without it a long identifier or path is cut to one line, and the path is what a reader acts on.
    block.insert("wrap".into(), true.into());
    Value::Object(block)
}

/// The workflow's attachment envelope around an Adaptive Card: a bare card posts nothing and reports success.
pub(crate) fn teams_envelope(card: Value) -> Value {
    // `contentUrl` is required by the envelope and always empty for an inline card.
    json!({"type": "message", "attachments": [{"contentType": ADAPTIVE_CARD, "contentUrl": "", "content": card}]})
}

/// `TeamsCard.of`: an Adaptive Card 1.4 in a Power Automate workflow's envelope.
pub fn teams(payload: &NotificationPayload, public_url: Option<&str>) -> Value {
    let mut body = vec![
        text_block(&chat_text::teams(text_of(payload)), "bolder", "large", "default", Some(false)),
        text_block(
            &chat_text::teams(&format!("{}  ·  scan #{}", target_of(payload), payload.scan_id)),
            "default",
            "small",
            "default",
            Some(true),
        ),
    ];
    let mut facts = vec![
        json!({"title": "New", "value": payload.new_count.to_string()}),
        json!({"title": "Reopened", "value": payload.reopened_count.to_string()}),
        json!({"title": "Resolved", "value": payload.resolved_count.to_string()}),
    ];
    if payload.kev_count > 0 {
        facts.push(json!({"title": "Actively exploited", "value": payload.kev_count.to_string()}));
    }
    facts.push(json!({"title": "Threshold", "value": payload.min_severity}));
    body.push(json!({"type": "FactSet", "facts": facts}));

    for issue in &payload.issues {
        let line = format!(
            "{}{} · {}",
            if issue.is_kev { "[exploited] " } else { "" },
            crate::java::to_upper_root(issue.severity.as_deref().unwrap_or("unknown")),
            subject_of(issue)
        );
        body.push(text_block(
            &chat_text::teams(&line),
            "bolder",
            "default",
            colour_of(issue.severity.as_deref()),
            Some(false),
        ));
        let context = chat_text::teams(&context(issue));
        if !context.is_empty() {
            body.push(text_block(&context, "default", "small", "default", Some(true)));
        }
    }
    if payload.truncated > 0 {
        body.push(text_block(&format!("and {} more", payload.truncated), "default", "small", "default", Some(true)));
    }

    let mut card = serde_json::Map::new();
    card.insert("type".into(), "AdaptiveCard".into());
    card.insert("$schema".into(), CARD_SCHEMA.into());
    card.insert("version".into(), "1.4".into());
    card.insert("body".into(), body.into());
    if let Some(base) = public_base(public_url) {
        card.insert(
            "actions".into(),
            json!([{"type": "Action.OpenUrl", "title": "Open in Vectispire", "url": format!("{base}/issues")}]),
        );
    }
    teams_envelope(Value::Object(card))
}

/// Where it is and what fixes it — the two things a reader acts on.
fn context(issue: &Detail) -> String {
    let present =
        |value: &Option<String>| value.as_deref().filter(|value| !crate::java::is_blank(value)).map(str::to_owned);
    let mut parts = Vec::new();
    parts.extend(present(&issue.package_name));
    parts.extend(present(&issue.file_path));
    parts.extend(present(&issue.fix_versions).map(|fix| format!("fixed in {fix}")));
    parts.join("  ·  ")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn payload() -> NotificationPayload {
        NotificationPayload {
            text: Some("Vectispire — web: 1 new issue(s)".into()),
            target: Some("web <!channel>".into()),
            scan_id: 3,
            new_count: 1,
            reopened_count: 0,
            resolved_count: 0,
            kev_count: 1,
            min_severity: Some("high".into()),
            issues: vec![Detail {
                id: 1,
                identifier: Some("CVE-1".into()),
                kind: Some("vulnerability".into()),
                severity: Some("critical".into()),
                is_kev: true,
                epss_score: Some(0.5),
                package_name: Some("[x](y)".into()),
                file_path: None,
                fix_versions: Some("2.0".into()),
                link: None,
            }],
            truncated: 2,
            message_id: Some("m".into()),
        }
    }

    #[test]
    fn values_are_inert_in_each_chat() {
        let slack = slack(&payload(), Some("https://v.example//")).to_string();
        assert!(slack.contains("web &lt;!channel&gt;"), "{slack}");
        assert!(slack.contains("https://v.example/issues"), "{slack}");
        let discord = discord(&payload(), None, Instant::of_epoch_second(0)).to_string();
        assert!(discord.contains(r"\\[x\\]\\(y\\)"), "{discord}");
        assert!(discord.contains("\"color\":14427686"), "{discord}");
        assert!(discord.contains("1970-01-01T00:00:00Z"), "{discord}");
        let teams = teams(&payload(), None).to_string();
        assert!(teams.contains("[x]\u{200B}(y)"), "{teams}");
        assert!(teams.contains("and 2 more"), "{teams}");
    }
}
