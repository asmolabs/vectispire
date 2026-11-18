//! `GitLabReviewReader` and `GitHubReviewReader`: one forge's answer to "how do changes reach this branch?" (decision
//! 0037, lot G3) — its settings where it offers them, and the history of what was merged, each change with its
//! approvals by people other than its author. **Every request goes through the pager it is handed**; the pager's
//! errors pass through untouched — a reading that did not happen, the previous one standing. **A refusal is an answer,
//! written down**; a 401 is the token's and makes the whole reading unreadable.

use std::collections::{BTreeSet, HashMap};

use serde_json::Value;
use vectispire_cp_outbound::pager::{NextPage, OutboundPager, PagerError};
use vectispire_domain::checklists::review::{ChangeReviewEvidence, History, MergedChange, Settings};
use vectispire_domain::instant::Instant;

use super::json::{as_text, path};
use super::path::segment;

/// What a reading found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Reading {
    Read(ChangeReviewEvidence),
    Unreadable(String),
}

fn instant(value: Option<&Value>) -> Option<Instant> {
    let text = value?.as_str()?;
    let parsed = time::OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339).ok()?;
    let utc = parsed.to_offset(time::UtcOffset::UTC);
    Some(Instant { epoch_second: utc.unix_timestamp(), nano: utc.nanosecond() })
}

fn approvals(count: i32) -> String {
    format!("{count} {}", if count == 1 { "approval" } else { "approvals" })
}

fn array(node: Option<&Value>) -> &[Value] {
    node.and_then(Value::as_array).map_or(&[], Vec::as_slice)
}

/// `asInt(default)`.
fn as_int(node: Option<&Value>, default: i32) -> i32 {
    match node {
        Some(Value::Number(number)) => number.as_i64().and_then(|n| i32::try_from(n).ok()).unwrap_or(default),
        Some(Value::String(text)) => text.trim().parse().unwrap_or(default),
        _ => default,
    }
}

/// `path(field).asText("")`: a missing or null node is `""`.
fn text_or_empty(node: Option<&Value>) -> String {
    match node {
        None | Some(Value::Null) => String::new(),
        other => as_text(other),
    }
}

/// A stated, non-blank text member.
fn stated_text(node: Option<&Value>, field: &str) -> Option<String> {
    path(node, field)
        .and_then(Value::as_str)
        .filter(|value| !vectispire_domain::java::is_blank(value))
        .map(str::to_owned)
}

fn evidence(
    forge: &str,
    project: String,
    branch: String,
    window_days: i32,
    settings: (Option<Settings>, Option<String>),
    history: (Option<History>, Option<String>),
) -> Reading {
    match ChangeReviewEvidence::new(
        forge.to_owned(),
        project,
        branch,
        window_days,
        settings.0,
        settings.1,
        history.0,
        history.1,
    ) {
        Ok(evidence) => Reading::Read(evidence),
        Err(defect) => Reading::Unreadable(defect.0),
    }
}

/// A source's reading: read, said why not, or the token rejected.
enum Source<T> {
    Read(T),
    Unread(String),
    Rejected,
}

// ── GitLab ───────────────────────────────────────────────────────────────────────────────────────────────────────

/// GitLab's "No one" in a protected branch's access levels.
const NO_ONE: i32 = 0;

fn gitlab_rejected() -> Reading {
    Reading::Unreadable(
        "GitLab rejected the connection's token (HTTP 401): it is wrong, expired or revoked. Replace it on the \
         connection."
            .into(),
    )
}

pub(crate) async fn read_gitlab(
    pager: &OutboundPager,
    api: &str,
    forge_id: &str,
    wanted: Option<&str>,
    since: Instant,
    window_days: i32,
    max_changes: usize,
) -> Result<Reading, PagerError> {
    let Some(id) = segment(Some(forge_id)) else {
        return Ok(Reading::Unreadable(format!("Project id \"{forge_id}\" cannot be named in a GitLab API path.")));
    };
    let project_url = format!("{api}/projects/{id}");
    let project = pager.get(&project_url).await?;
    match project.status {
        200 => {}
        401 => return Ok(gitlab_rejected()),
        status => {
            return Ok(Reading::Unreadable(format!(
                "GitLab does not show project {forge_id} to the connection's token (HTTP {status}): deleted, moved out \
                 of the token's reach, or its access revoked."
            )));
        }
    }
    let body = project.body.as_ref();
    let full_path = match path(body, "path_with_namespace") {
        None | Some(Value::Null) => forge_id.to_owned(),
        other => as_text(other),
    };
    let branch = wanted.map(str::to_owned).or_else(|| stated_text(body, "default_branch"));
    let Some(branch) = branch else {
        return Ok(Reading::Unreadable(format!(
            "GitLab names no default branch for {full_path}: the repository is empty."
        )));
    };
    let Some(branch_segment) = segment(Some(&branch)) else {
        return Ok(Reading::Unreadable(format!(
            "Branch \"{branch}\" of {full_path} cannot be named in a GitLab API path."
        )));
    };
    let settings = match gitlab_settings(pager, &project_url, &branch, &branch_segment).await? {
        Source::Read(settings) => (Some(settings), None),
        Source::Unread(why) => (None, Some(why)),
        Source::Rejected => return Ok(gitlab_rejected()),
    };
    let history = match gitlab_history(pager, &project_url, &branch_segment, since, max_changes).await? {
        Source::Read(history) => (Some(history), None),
        Source::Unread(why) => (None, Some(why)),
        Source::Rejected => return Ok(gitlab_rejected()),
    };
    Ok(evidence("gitlab", full_path, branch, window_days, settings, history))
}

async fn gitlab_settings(
    pager: &OutboundPager,
    project_url: &str,
    branch: &str,
    branch_segment: &str,
) -> Result<Source<Settings>, PagerError> {
    let configuration = pager.get(&format!("{project_url}/approvals")).await?;
    match configuration.status {
        200 => {}
        401 => return Ok(Source::Rejected),
        404 => {
            return Ok(Source::Unread(
                "GitLab answers no approval settings (HTTP 404): Community Edition or Free tier, which has no approval \
                 rule — judged on the history"
                    .into(),
            ));
        }
        status => {
            return Ok(Source::Unread(format!("GitLab refused the approval settings to this token (HTTP {status})")));
        }
    }
    // true means the author MAY approve; a field GitLab did not state is not "prevented".
    let author_prevented = path(configuration.body.as_ref(), "merge_requests_author_approval")
        .and_then(Value::as_bool)
        .is_some_and(|may| !may);
    let protection = pager.get(&format!("{project_url}/protected_branches/{branch_segment}")).await?;
    let (protected_branch, push_refused, push) = match protection.status {
        200 => {
            let refused = push_refused(protection.body.as_ref());
            (true, refused, if refused { "direct push refused".to_owned() } else { "direct push allowed".to_owned() })
        }
        401 => return Ok(Source::Rejected),
        404 => (false, false, "branch not protected".to_owned()),
        status => (false, false, format!("protection not readable (HTTP {status})")),
    };
    let rules = pager.get(&format!("{project_url}/approval_rules?per_page=100")).await?;
    let mut required = 0;
    match rules.status {
        200 => {
            for rule in array(rules.body.as_ref()) {
                if applies(rule, branch, protected_branch) {
                    required = required.max(as_int(rule.get("approvals_required"), 0));
                }
            }
        }
        401 => return Ok(Source::Rejected),
        status => {
            return Ok(Source::Unread(format!("GitLab refused the approval rules to this token (HTTP {status})")));
        }
    }
    let described = format!(
        "GitLab approval rules require {} on {branch}, {}, {push}",
        approvals(required),
        if author_prevented { "author approval prevented" } else { "author approval allowed" }
    );
    Ok(Source::Read(Settings {
        required_approvals: required,
        author_approval_prevented: author_prevented,
        direct_push_refused: push_refused,
        described,
    }))
}

/// Whether a rule binds the branch: a regular or any-approver rule naming no branch binds them all; one naming "all
/// protected branches" binds a protected one; one naming branches binds those, a wildcard as GitLab writes it.
pub(crate) fn applies(rule: &Value, branch: &str, protected_branch: bool) -> bool {
    let kind = match rule.get("rule_type") {
        None | Some(Value::Null) => "regular".to_owned(),
        other => as_text(other),
    };
    if kind != "regular" && kind != "any_approver" {
        return false;
    }
    if super::json::as_boolean(rule.get("applies_to_all_protected_branches"), false) {
        return protected_branch;
    }
    let named = array(rule.get("protected_branches"));
    if named.is_empty() {
        return true;
    }
    named.iter().any(|branch_rule| wildcard(&text_or_empty(branch_rule.get("name")), branch))
}

/// GitLab's protected-branch wildcard: `*` any run of characters, every other character itself, case included —
/// matched by hand over UTF-16 units, backtracking to the last star only.
pub(crate) fn wildcard(pattern: &str, branch: &str) -> bool {
    let pattern: Vec<u16> = pattern.encode_utf16().collect();
    let branch: Vec<u16> = branch.encode_utf16().collect();
    let star_unit = u16::from(b'*');
    let (mut b, mut p, mut resume) = (0usize, 0usize, 0usize);
    let mut star: Option<usize> = None;
    while b < branch.len() {
        if p < pattern.len() && pattern[p] != star_unit && pattern[p] == branch[b] {
            p += 1;
            b += 1;
        } else if p < pattern.len() && pattern[p] == star_unit {
            star = Some(p);
            p += 1;
            resume = b;
        } else if let Some(at) = star {
            p = at + 1;
            resume += 1;
            b = resume;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == star_unit {
        p += 1;
    }
    p == pattern.len()
}

/// "No one" in every push level, and no user, group or deploy key let through by name.
fn push_refused(protection: Option<&Value>) -> bool {
    let Some(levels) = path(protection, "push_access_levels").and_then(Value::as_array) else {
        return false;
    };
    let stated = |level: &Value, field: &str| level.get(field).is_some_and(|value| !value.is_null());
    levels.iter().all(|level| {
        as_int(level.get("access_level"), -1) == NO_ONE
            && !stated(level, "user_id")
            && !stated(level, "group_id")
            && !stated(level, "deploy_key_id")
    })
}

async fn gitlab_history(
    pager: &OutboundPager,
    project_url: &str,
    branch_segment: &str,
    since: Instant,
    max_changes: usize,
) -> Result<Source<History>, PagerError> {
    let mut merged: Vec<(String, Instant, String)> = Vec::new();
    let mut complete = true;
    let since_text = since.to_java_string().unwrap_or_default();
    let mut url = Some(format!(
        "{project_url}/merge_requests?state=merged&target_branch={branch_segment}&updated_after={since_text}\
         &order_by=updated_at&sort=desc&per_page=100"
    ));
    'pages: while let Some(current) = url {
        let page = pager.get(&current).await?;
        match page.status {
            200 => {}
            401 => return Ok(Source::Rejected),
            status => {
                return Ok(Source::Unread(format!(
                    "GitLab refused the merge requests to this token (HTTP {status}): it needs the read_api scope and \
                     at least the Reporter role on the project"
                )));
            }
        }
        let Some(Value::Array(requests)) = page.body.as_ref() else {
            return Err(PagerError::Failure("GitLab answered the merge requests with no list.".into()));
        };
        for request in requests {
            let at = instant(request.get("merged_at"))
                .or_else(|| instant(request.get("closed_at")))
                .or_else(|| instant(request.get("updated_at")));
            let Some(at) = at.filter(|at| *at >= since) else {
                continue;
            };
            if merged.len() == max_changes {
                complete = false;
                break 'pages;
            }
            merged.push((
                text_or_empty(request.get("iid")),
                at,
                text_or_empty(request.get("author").and_then(|author| author.get("id"))),
            ));
        }
        url = pager.next(&page, &current, NextPage::Gitlab);
    }
    let mut changes = Vec::with_capacity(merged.len());
    for (iid, at, author) in merged {
        let Some(number) = segment(Some(&iid)) else {
            return Ok(Source::Unread(
                "GitLab answered a merge request without a number to ask its approvals by".into(),
            ));
        };
        let answered = pager.get(&format!("{project_url}/merge_requests/{number}/approvals")).await?;
        match answered.status {
            200 => {}
            401 => return Ok(Source::Rejected),
            status => {
                return Ok(Source::Unread(format!(
                    "GitLab refused the approvals of !{iid} to this token (HTTP {status})"
                )));
            }
        }
        let mut peers = BTreeSet::new();
        let mut author_approved = false;
        for approval in array(path(answered.body.as_ref(), "approved_by")) {
            let approver = text_or_empty(approval.get("user").and_then(|user| user.get("id")));
            if approver.is_empty() {
                continue;
            }
            if approver == author {
                author_approved = true;
            } else {
                peers.insert(approver);
            }
        }
        changes.push(MergedChange {
            reference: format!("!{iid}"),
            merged_at: at,
            peer_approvals: i32::try_from(peers.len()).unwrap_or(i32::MAX),
            author_approved,
        });
    }
    // Newest first, a stable sort as Java's.
    changes.sort_by_key(|change| std::cmp::Reverse(change.merged_at));
    Ok(Source::Read(History { complete, changes }))
}

// ── GitHub ───────────────────────────────────────────────────────────────────────────────────────────────────────

fn github_rejected() -> Reading {
    Reading::Unreadable(
        "GitHub rejected the connection's token (HTTP 401): it is wrong, expired or revoked. Replace it on the \
         connection."
            .into(),
    )
}

pub(crate) async fn read_github(
    pager: &OutboundPager,
    api: &str,
    forge_id: &str,
    wanted: Option<&str>,
    since: Instant,
    window_days: i32,
    max_changes: usize,
) -> Result<Reading, PagerError> {
    let Some(id) = segment(Some(forge_id)) else {
        return Ok(Reading::Unreadable(format!("Repository id \"{forge_id}\" cannot be named in a GitHub API path.")));
    };
    let repository = pager.get(&format!("{api}/repositories/{id}")).await?;
    match repository.status {
        200 => {}
        401 => return Ok(github_rejected()),
        status => {
            return Ok(Reading::Unreadable(format!(
                "GitHub does not show repository {forge_id} to the connection's token (HTTP {status}): deleted, \
                 transferred out of the token's reach, or its access revoked."
            )));
        }
    }
    let body = repository.body.as_ref();
    let Some(full_name) = stated_text(body, "full_name").filter(|name| name.contains('/')) else {
        return Ok(Reading::Unreadable(format!("GitHub answered repository {forge_id} without its full name.")));
    };
    let Some(branch) = wanted.map(str::to_owned).or_else(|| stated_text(body, "default_branch")) else {
        return Ok(Reading::Unreadable(format!("GitHub names no default branch for {full_name}.")));
    };
    let (owner_name, repo_name) = full_name.split_once('/').unwrap_or((&full_name, ""));
    let (Some(owner), Some(name), Some(branch_segment)) =
        (segment(Some(owner_name)), segment(Some(repo_name)), segment(Some(&branch)))
    else {
        return Ok(Reading::Unreadable(format!(
            "GitHub named repository {full_name} or its branch {branch} in a form no API path can carry."
        )));
    };
    let repo = format!("{api}/repos/{owner}/{name}");
    let mut unread_settings = Vec::new();
    let mut from_rules = -1;
    let rules = pager.get(&format!("{repo}/rules/branches/{branch_segment}?per_page=100")).await?;
    match rules.status {
        200 => {
            from_rules = 0;
            for rule in array(rules.body.as_ref()) {
                if rule.get("type").and_then(Value::as_str) == Some("pull_request") {
                    from_rules = from_rules.max(as_int(
                        rule.get("parameters").and_then(|parameters| parameters.get("required_approving_review_count")),
                        0,
                    ));
                }
            }
        }
        401 => return Ok(github_rejected()),
        status => unread_settings.push(format!("the rules of the branch not readable (HTTP {status})")),
    }
    let mut from_protection = -1;
    let mut admins_bound = false;
    let protection = pager.get(&format!("{repo}/branches/{branch_segment}/protection")).await?;
    match protection.status {
        200 => {
            let found = protection.body.as_ref();
            from_protection =
                as_int(path(path(found, "required_pull_request_reviews"), "required_approving_review_count"), 0);
            admins_bound = super::json::as_boolean(path(path(found, "enforce_admins"), "enabled"), false);
        }
        401 => return Ok(github_rejected()),
        // GitHub's "Branch not protected".
        404 => from_protection = 0,
        status => unread_settings
            .push(format!("the branch protection not readable (HTTP {status}): it needs Administration: read")),
    }
    let settings = if from_rules >= 0 || from_protection >= 0 {
        let required = from_rules.max(if admins_bound { from_protection } else { -1 }).max(0);
        let mut said = Vec::new();
        if from_rules >= 0 {
            said.push(format!("rulesets require {}", approvals(from_rules)));
        }
        if from_protection >= 0 {
            said.push(format!(
                "branch protection requires {}{}",
                approvals(from_protection),
                if from_protection > 0 && !admins_bound { ", administrators exempt" } else { "" }
            ));
        }
        said.extend(unread_settings.iter().cloned());
        (
            Some(Settings {
                required_approvals: required,
                author_approval_prevented: true,
                direct_push_refused: required > 0,
                described: format!("{} on {branch}, author approval prevented by GitHub", said.join(", ")),
            }),
            None,
        )
    } else {
        (None, Some(unread_settings.join("; ")))
    };
    let history = match github_history(pager, &repo, &branch_segment, since, max_changes).await? {
        Source::Read(history) => (Some(history), None),
        Source::Unread(why) => (None, Some(why)),
        Source::Rejected => return Ok(github_rejected()),
    };
    Ok(evidence("github", full_name.clone(), branch, window_days, settings, history))
}

async fn github_history(
    pager: &OutboundPager,
    repo: &str,
    branch_segment: &str,
    since: Instant,
    max_changes: usize,
) -> Result<Source<History>, PagerError> {
    let mut merged: Vec<(i64, Instant, String)> = Vec::new();
    let mut complete = true;
    let mut url =
        Some(format!("{repo}/pulls?state=closed&base={branch_segment}&sort=updated&direction=desc&per_page=100"));
    'pages: while let Some(current) = url {
        let page = pager.get(&current).await?;
        match page.status {
            200 => {}
            401 => return Ok(Source::Rejected),
            status => {
                return Ok(Source::Unread(format!(
                    "GitHub refused the pull requests to this token (HTTP {status}): a fine-grained token needs Pull \
                     requests: read"
                )));
            }
        }
        let Some(Value::Array(requests)) = page.body.as_ref() else {
            return Err(PagerError::Failure("GitHub answered the pull requests with no list.".into()));
        };
        for request in requests {
            // Sorted by update, newest first: everything after one updated before the window was too.
            if instant(request.get("updated_at")).is_some_and(|updated| updated < since) {
                break 'pages;
            }
            let Some(at) = instant(request.get("merged_at")).filter(|at| *at >= since) else {
                continue;
            };
            if merged.len() == max_changes {
                complete = false;
                break 'pages;
            }
            merged.push((
                request.get("number").and_then(Value::as_i64).unwrap_or(0),
                at,
                text_or_empty(request.get("user").and_then(|user| user.get("id"))),
            ));
        }
        url = pager.next(&page, &current, NextPage::Link);
    }
    let mut changes = Vec::with_capacity(merged.len());
    for (number, at, author) in merged {
        // A reviewer's latest decision stands; a comment decides nothing.
        let mut decided: HashMap<String, String> = HashMap::new();
        let mut reviews = Some(format!("{repo}/pulls/{number}/reviews?per_page=100"));
        while let Some(current) = reviews {
            let page = pager.get(&current).await?;
            match page.status {
                200 => {}
                401 => return Ok(Source::Rejected),
                status => {
                    return Ok(Source::Unread(format!(
                        "GitHub refused the reviews of #{number} to this token (HTTP {status}): a fine-grained token \
                         needs Pull requests: read"
                    )));
                }
            }
            for review in array(page.body.as_ref()) {
                let reviewer = text_or_empty(review.get("user").and_then(|user| user.get("id")));
                let Some(state) = stated_text(Some(review), "state") else {
                    continue;
                };
                if reviewer.is_empty() {
                    continue;
                }
                if matches!(state.as_str(), "APPROVED" | "CHANGES_REQUESTED" | "DISMISSED") {
                    decided.insert(reviewer, state);
                }
            }
            reviews = pager.next(&page, &current, NextPage::Link);
        }
        let mut peers = 0;
        let mut author_approved = false;
        for (reviewer, decision) in &decided {
            if decision != "APPROVED" {
                continue;
            }
            if *reviewer == author {
                author_approved = true;
            } else {
                peers += 1;
            }
        }
        changes.push(MergedChange {
            reference: format!("#{number}"),
            merged_at: at,
            peer_approvals: peers,
            author_approved,
        });
    }
    changes.sort_by_key(|change| std::cmp::Reverse(change.merged_at));
    Ok(Source::Read(History { complete, changes }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gitlab_wildcards_match_by_hand() {
        assert!(wildcard("release/*", "release/1.2"));
        assert!(wildcard("main", "main"));
        assert!(!wildcard("Main", "main"));
        assert!(wildcard("*", ""));
        assert!(!wildcard("release/*", "hotfix/1"));
        assert!(!wildcard(&"*a".repeat(9), &"a".repeat(8)));
        assert!(wildcard(&"*a".repeat(9), &"a".repeat(60)));
    }

    #[test]
    fn a_rule_binds_the_branches_it_names() {
        let any = serde_json::json!({"rule_type": "any_approver", "approvals_required": 2});
        assert!(applies(&any, "main", false));
        let owners = serde_json::json!({"rule_type": "code_owner"});
        assert!(!applies(&owners, "main", false));
        let protected = serde_json::json!({"applies_to_all_protected_branches": true});
        assert!(applies(&protected, "main", true) && !applies(&protected, "main", false));
        let named = serde_json::json!({"protected_branches": [{"name": "release/*"}]});
        assert!(applies(&named, "release/2", false) && !applies(&named, "main", true));
    }

    #[test]
    fn push_is_refused_only_when_no_one_may_push() {
        assert!(push_refused(Some(&serde_json::json!({"push_access_levels": [{"access_level": 0}]}))));
        assert!(!push_refused(Some(&serde_json::json!({"push_access_levels": [{"access_level": 40}]}))));
        assert!(!push_refused(Some(&serde_json::json!({"push_access_levels": [{"access_level": 0, "user_id": 3}]}))));
        assert!(!push_refused(Some(&serde_json::json!({}))));
    }
}
