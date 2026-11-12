//! `ChangeReviewEvidence`: what one reading of a forge said about how changes reach one branch of one repository —
//! the evidence a `change_review` line is judged on (decision 0037, lot G3). Read by `forges` through the
//! connection's token, stored as written, read back here for the rule.
//!
//! **Two sources, each one absent rather than empty when it was not read**: the settings (a configuration proof)
//! and the history (what was merged, with each change's approvals by people other than its author). A source that
//! could not be read says why; "not read" is never "nothing to read" (decision 0007). No person's name is kept.

use serde_json::Value;

use crate::checklists::Defect;
use crate::checklists::jackson;
use crate::instant::Instant;
use crate::wire::write_string;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeReviewEvidence {
    /// `gitlab` or `github`: how a change is named, merge request or pull request.
    pub forge: String,
    /// The forge's full path of the repository, as the forge named it when read.
    pub project: String,
    /// The branch read — the rule's, or the default branch the forge named.
    pub branch: String,
    /// How many days back from the reading the history reaches.
    pub window_days: i32,
    pub settings: Option<Settings>,
    pub settings_unread: Option<String>,
    pub history: Option<History>,
    pub history_unread: Option<String>,
}

/// The branch's configuration, as the forge stated it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// The approvals a merge into the branch requires — the largest any applicable rule asks; 0 where none does.
    pub required_approvals: i32,
    /// Whether the author's own approval is refused (always on GitHub).
    pub author_approval_prevented: bool,
    /// Whether a change can reach the branch only through a reviewed merge.
    pub direct_push_refused: bool,
    /// The configuration in one sentence, for the evidence.
    pub described: String,
}

impl Settings {
    /// Whether this configuration alone guarantees `minimum_approvals` peers on every change.
    pub fn proves(&self, minimum_approvals: i32) -> bool {
        self.required_approvals >= minimum_approvals && self.author_approval_prevented && self.direct_push_refused
    }
}

/// The changes merged into the branch within the window, newest first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct History {
    /// False when the window held more changes than one reading takes: the counts are then not the window's.
    pub complete: bool,
    pub changes: Vec<MergedChange>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergedChange {
    /// `!12` on GitLab, `#12` on GitHub.
    pub reference: String,
    pub merged_at: Instant,
    /// Distinct people other than the author whose approval stood when it was read.
    pub peer_approvals: i32,
    /// Whether the author approved their own change — counted nowhere, named in the evidence.
    pub author_approved: bool,
}

impl ChangeReviewEvidence {
    /// The reading, refused as a defect when a source neither was read nor says why it was not.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        forge: String,
        project: String,
        branch: String,
        window_days: i32,
        settings: Option<Settings>,
        settings_unread: Option<String>,
        history: Option<History>,
        history_unread: Option<String>,
    ) -> Result<ChangeReviewEvidence, Defect> {
        if settings.is_some() == settings_unread.is_some() || history.is_some() == history_unread.is_some() {
            return Err(Defect("Each source is either read or says why it was not.".to_owned()));
        }
        Ok(ChangeReviewEvidence {
            forge,
            project,
            branch,
            window_days,
            settings,
            settings_unread,
            history,
            history_unread,
        })
    }

    /// What the forge calls one change: a merge request on GitLab, a pull request elsewhere.
    pub fn changes(&self) -> &'static str {
        if self.forge == "gitlab" { "merge requests" } else { "pull requests" }
    }

    /// As stored: what the measurement's digest covers, so it is written one way — Jackson's, member by member.
    pub fn json(&self) -> String {
        let mut out = String::from("{\"forge\":");
        write_string(&mut out, &self.forge);
        out.push_str(",\"project\":");
        write_string(&mut out, &self.project);
        out.push_str(",\"branch\":");
        write_string(&mut out, &self.branch);
        out.push_str(&format!(",\"windowDays\":{},\"settings\":", self.window_days));
        match &self.settings {
            None => out.push_str("null"),
            Some(read) => {
                out.push_str(&format!(
                    "{{\"requiredApprovals\":{},\"authorApprovalPrevented\":{},\"directPushRefused\":{},\"described\":",
                    read.required_approvals, read.author_approval_prevented, read.direct_push_refused
                ));
                write_string(&mut out, &read.described);
                out.push('}');
            }
        }
        out.push_str(",\"settingsUnread\":");
        optional(&mut out, self.settings_unread.as_deref());
        out.push_str(",\"history\":");
        match &self.history {
            None => out.push_str("null"),
            Some(read) => {
                out.push_str(&format!("{{\"complete\":{},\"changes\":[", read.complete));
                for (index, change) in read.changes.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    out.push_str("{\"reference\":");
                    write_string(&mut out, &change.reference);
                    out.push_str(",\"mergedAt\":");
                    write_string(&mut out, &change.merged_at.to_java_string().unwrap_or_default());
                    out.push_str(&format!(
                        ",\"peerApprovals\":{},\"authorApproved\":{}}}",
                        change.peer_approvals, change.author_approved
                    ));
                }
                out.push_str("]}");
            }
        }
        out.push_str(",\"historyUnread\":");
        optional(&mut out, self.history_unread.as_deref());
        out.push('}');
        out
    }

    /// A stored reading read back, as [`json`](ChangeReviewEvidence::json) wrote it; a row that does not read is a
    /// defect.
    pub fn read(stored: &str) -> Result<ChangeReviewEvidence, Defect> {
        let node = jackson::read_tree(stored)
            .map_err(|_| Defect("A stored change-review reading does not read as JSON.".to_owned()))?
            .unwrap_or(Value::Null);
        let settings = jackson::get(&node, "settings").filter(|value| value.is_object()).map(|read| Settings {
            required_approvals: jackson::as_int(jackson::get(read, "requiredApprovals")),
            author_approval_prevented: jackson::as_boolean(jackson::get(read, "authorApprovalPrevented")),
            direct_push_refused: jackson::as_boolean(jackson::get(read, "directPushRefused")),
            described: jackson::get(read, "described")
                .filter(|value| !value.is_null())
                .map_or_else(String::new, |value| jackson::as_text(Some(value))),
        });
        let history = match jackson::get(&node, "history").filter(|value| value.is_object()) {
            None => None,
            Some(read) => {
                let mut changes = Vec::new();
                for entry in jackson::get(read, "changes").and_then(Value::as_array).into_iter().flatten() {
                    let merged_at = jackson::as_text(jackson::get(entry, "mergedAt"));
                    changes.push(MergedChange {
                        reference: jackson::as_text(jackson::get(entry, "reference")),
                        merged_at: Instant::parse_java(&merged_at)
                            .ok_or_else(|| Defect(format!("Text '{merged_at}' could not be parsed")))?,
                        peer_approvals: jackson::as_int(jackson::get(entry, "peerApprovals")),
                        author_approved: jackson::as_boolean(jackson::get(entry, "authorApproved")),
                    });
                }
                Some(History { complete: jackson::as_boolean(jackson::get(read, "complete")), changes })
            }
        };
        ChangeReviewEvidence::new(
            crate::java::to_lower_root(&jackson::as_text(jackson::get(&node, "forge"))),
            jackson::as_text(jackson::get(&node, "project")),
            jackson::as_text(jackson::get(&node, "branch")),
            jackson::as_int(jackson::get(&node, "windowDays")),
            settings,
            jackson::text(&node, "settingsUnread"),
            history,
            jackson::text(&node, "historyUnread"),
        )
    }
}

fn optional(out: &mut String, value: Option<&str>) {
    match value {
        None => out.push_str("null"),
        Some(text) => write_string(out, text),
    }
}
