//! `GitLabLister` and `GitHubLister`: one forge's listing of namespaces and repositories (decision 0037 §3), written
//! into the run as it goes, page by page, every request through the [`OutboundPager`] the run hands out.
//!
//! **GitLab**: the groups the token belongs to, then its projects through one keyset listing — `membership=true` and
//! `min_access_level=10` are not optional, or gitlab.com lists millions of other people's projects — then the
//! language of the projects worth asking about. **GitHub**: per owner, one organisation at a time; a fine-grained
//! token sees the connection's owner only, a classic one every organisation its user belongs to. **A namespace the
//! token cannot read is not a failed run**: it is recorded unreadable and none of its repositories is marked gone.
//! **What a forge leaves out stays unknown.**

use serde_json::Value;
use vectispire_cp_outbound::json::Answer;
use vectispire_cp_outbound::pager::{NextPage, OutboundPager, PagerError};
use vectispire_domain::forges::{DiscoveredRepository, DiscoveryReason};
use vectispire_domain::instant::Instant;

use super::path;
use super::probes::GITHUB_API_VERSION;

pub(crate) const GITLAB_GROUPS: &str = "/groups?min_access_level=10&order_by=id&sort=asc&per_page=100";
pub(crate) const GITLAB_PROJECTS: &str =
    "/projects?membership=true&min_access_level=10&statistics=true&pagination=keyset&order_by=id&sort=asc&per_page=100";
pub(crate) const GITHUB_USER: &str = "/user";
pub(crate) const GITHUB_USER_ORGS: &str = "/user/orgs?per_page=100";
pub(crate) const GITHUB_USER_REPOS: &str = "/user/repos?affiliation=owner&visibility=all&sort=full_name&per_page=100";

/// Why a listing cannot go on.
#[derive(Debug)]
pub(crate) enum ListError {
    /// The pager's: a page elsewhere, a long rate limit, the deadline, a forge that does not answer.
    Pager(PagerError),
    /// A status that ends the run, with its reason.
    Refused(DiscoveryReason, String),
    /// The run's repository bound was reached; what fitted under it is kept.
    BoundReached(String),
    /// The run is no longer this instance's: stop, write nothing more.
    LeaseLost,
    /// The database failed.
    Store(String),
}

impl From<PagerError> for ListError {
    fn from(error: PagerError) -> ListError {
        match error {
            PagerError::Stopped(_) => ListError::LeaseLost,
            other => ListError::Pager(other),
        }
    }
}

/// What a listing writes to, and where its requests come from — the run.
pub(crate) trait Listing: Send {
    fn api_root(&self) -> &str;
    fn owner(&self) -> Option<&str>;
    fn token(&self) -> &str;
    fn pager(&mut self, credential: Vec<(String, String)>) -> Result<OutboundPager, ListError>;
    fn namespace(&mut self, path: &str);
    fn unreadable(&mut self, path: &str, reason: &str);
    fn namespaces_incomplete(&mut self, reason: &str);
    fn repositories(
        &mut self,
        page: Vec<DiscoveredRepository>,
    ) -> impl std::future::Future<Output = Result<(), ListError>> + Send;
    fn languages_wanted(&self) -> Vec<String>;
    fn language(
        &mut self,
        forge_id: &str,
        language: Option<String>,
    ) -> impl std::future::Future<Output = Result<(), ListError>> + Send;
}

/// `node.path(field)` read as the listers read it: a non-blank text, or a number's spelling.
fn text(node: Option<&Value>, field: &str) -> Option<String> {
    match node.and_then(|node| node.get(field)) {
        Some(Value::String(value)) if !vectispire_domain::java::is_blank(value) => Some(value.clone()),
        Some(Value::Number(number)) => Some(number.to_string()),
        _ => None,
    }
}

fn id_of(node: &Value) -> String {
    match node.get("id") {
        Some(Value::Number(number)) if number.is_i64() || number.is_u64() => number.to_string(),
        _ => text(Some(node), "id").unwrap_or_default(),
    }
}

fn flag(node: Option<&Value>) -> Option<bool> {
    node.and_then(Value::as_bool)
}

/// `OffsetDateTime.parse(value).toInstant()`; `None` when unreadable.
fn instant(value: Option<String>) -> Option<Instant> {
    let parsed = time::OffsetDateTime::parse(value.as_deref()?, &time::format_description::well_known::Rfc3339).ok()?;
    let utc = parsed.to_offset(time::UtcOffset::UTC);
    Some(Instant { epoch_second: utc.unix_timestamp(), nano: utc.nanosecond() })
}

fn list_of(answer: Answer, missing: impl FnOnce() -> ListError) -> Result<Vec<Value>, ListError> {
    match answer.body {
        Some(Value::Array(items)) => Ok(items),
        _ => Err(missing()),
    }
}

// ── GitLab ───────────────────────────────────────────────────────────────────────────────────────────────────────

fn gitlab_rejected() -> ListError {
    ListError::Refused(
        DiscoveryReason::TokenRejected,
        "GitLab rejected this token (HTTP 401): it is wrong, expired or revoked. Replace it on the connection.".into(),
    )
}

/// Every page of a GitLab listing.
async fn gitlab_walk(
    pager: &OutboundPager,
    first: String,
    what: &str,
    mut page: impl FnMut(Vec<Value>) -> Vec<Value>,
) -> Result<Vec<Vec<Value>>, ListError> {
    let mut pages = Vec::new();
    let mut url = Some(first);
    while let Some(current) = url {
        let answer = pager.get(&current).await?;
        match answer.status {
            200 => {}
            401 => return Err(gitlab_rejected()),
            403 | 404 => {
                return Err(ListError::Refused(
                    DiscoveryReason::ForgeRefused,
                    format!(
                        "GitLab refused to list {what} with this token (HTTP {}): it needs the read_api scope.",
                        answer.status
                    ),
                ));
            }
            status => {
                return Err(ListError::Refused(
                    DiscoveryReason::ForgeRefused,
                    format!("GitLab answered the listing of {what} with HTTP {status}."),
                ));
            }
        }
        let next = pager.next(&answer, &current, NextPage::Gitlab);
        let items = list_of(answer, || {
            ListError::Refused(
                DiscoveryReason::ForgeUnavailable,
                format!("GitLab answered the listing of {what} with no list."),
            )
        })?;
        pages.push(page(items));
        url = next;
    }
    Ok(pages)
}

pub(crate) async fn list_gitlab(listing: &mut impl Listing) -> Result<(), ListError> {
    let api = listing.api_root().to_owned();
    let pager = listing.pager(vec![("PRIVATE-TOKEN".to_owned(), listing.token().to_owned())])?;
    for group_page in gitlab_walk(&pager, format!("{api}{GITLAB_GROUPS}"), "the groups", |items| items).await? {
        for group in &group_page {
            if let Some(path) = text(Some(group), "full_path") {
                listing.namespace(&path);
            }
        }
    }
    // The projects are written page by page, as they come: a bound reached stops the listing where it is.
    let mut url = Some(format!("{api}{GITLAB_PROJECTS}"));
    while let Some(current) = url {
        let answer = pager.get(&current).await?;
        match answer.status {
            200 => {}
            401 => return Err(gitlab_rejected()),
            403 | 404 => {
                return Err(ListError::Refused(
                    DiscoveryReason::ForgeRefused,
                    format!(
                        "GitLab refused to list the projects with this token (HTTP {}): it needs the read_api scope.",
                        answer.status
                    ),
                ));
            }
            status => {
                return Err(ListError::Refused(
                    DiscoveryReason::ForgeRefused,
                    format!("GitLab answered the listing of the projects with HTTP {status}."),
                ));
            }
        }
        let next = pager.next(&answer, &current, NextPage::Gitlab);
        let items = list_of(answer, || {
            ListError::Refused(
                DiscoveryReason::ForgeUnavailable,
                "GitLab answered the listing of the projects with no list.".into(),
            )
        })?;
        let mut repositories = Vec::with_capacity(items.len());
        for project in &items {
            let repository = gitlab_repository(project);
            listing.namespace(&repository.namespace_path.clone());
            repositories.push(repository);
        }
        listing.repositories(repositories).await?;
        url = next;
    }
    for forge_id in listing.languages_wanted() {
        // The id is the forge's own, read from its listing: encoded all the same.
        let Some(segment) = path::segment(Some(&forge_id)) else {
            listing.language(&forge_id, None).await?;
            continue;
        };
        let answer = pager.get(&format!("{api}/projects/{segment}/languages")).await?;
        match answer.status {
            200 => {
                let main = main_language(answer.body.as_ref());
                listing.language(&forge_id, main).await?;
            }
            401 => return Err(gitlab_rejected()),
            // A Guest cannot read a private project's languages; a project gone since has none. Unknown.
            _ => listing.language(&forge_id, None).await?,
        }
    }
    Ok(())
}

pub(crate) fn gitlab_repository(project: &Value) -> DiscoveredRepository {
    let full_path = text(Some(project), "path_with_namespace").unwrap_or_default();
    let namespace = project.get("namespace");
    let namespace_path = text(namespace, "full_path")
        .unwrap_or_else(|| full_path.rsplit_once('/').map_or_else(String::new, |(namespace, _)| namespace.to_owned()));
    let size = project.get("statistics").and_then(|statistics| statistics.get("repository_size"));
    DiscoveredRepository {
        forge_id: id_of(project),
        full_path: full_path.clone(),
        namespace_path,
        personal: text(namespace, "kind").as_deref() == Some("user"),
        name: text(Some(project), "name").or_else(|| text(Some(project), "path")).unwrap_or_default(),
        default_branch: text(Some(project), "default_branch"),
        archived: flag(project.get("archived")),
        fork: project.get("forked_from_project").filter(|source| source.is_object()).map(|_| true),
        visibility: text(Some(project), "visibility"),
        last_activity_at: instant(text(Some(project), "last_activity_at")),
        language: None,
        size_bytes: size.and_then(Value::as_i64),
        http_url: text(Some(project), "http_url_to_repo"),
        ssh_url: text(Some(project), "ssh_url_to_repo"),
        web_url: text(Some(project), "web_url"),
    }
}

/// The language with the largest share, the first of equal ones in the document's order.
pub(crate) fn main_language(languages: Option<&Value>) -> Option<String> {
    let Some(Value::Object(shares)) = languages else {
        return None;
    };
    let mut best: Option<(&String, f64)> = None;
    for (language, share) in shares {
        if let Some(share) = share.as_f64()
            && best.is_none_or(|(_, top)| share > top)
        {
            best = Some((language, share));
        }
    }
    best.map(|(language, _)| language.clone())
}

// ── GitHub ───────────────────────────────────────────────────────────────────────────────────────────────────────

fn github_rejected() -> ListError {
    ListError::Refused(
        DiscoveryReason::TokenRejected,
        "GitHub rejected this token (HTTP 401): it is wrong, expired or revoked. Replace it on the connection.".into(),
    )
}

pub(crate) async fn list_github(listing: &mut impl Listing) -> Result<(), ListError> {
    let api = listing.api_root().to_owned();
    let pager = listing.pager(vec![
        ("Authorization".to_owned(), format!("Bearer {}", listing.token())),
        ("X-GitHub-Api-Version".to_owned(), GITHUB_API_VERSION.to_owned()),
    ])?;
    let own = pager.get(&format!("{api}{GITHUB_USER}")).await?;
    match own.status {
        200 => {}
        401 => return Err(github_rejected()),
        status => {
            return Err(ListError::Refused(
                DiscoveryReason::ForgeRefused,
                format!(
                    "GitHub refused to name the token's user (HTTP {status}): the discovery cannot tell its own \
                     repositories from an organisation's."
                ),
            ));
        }
    }
    let login = text(own.body.as_ref(), "login").ok_or_else(|| {
        ListError::Refused(DiscoveryReason::ForgeUnavailable, "GitHub answered the token's user with no login.".into())
    })?;
    let classic = own.header("x-oauth-scopes").is_some();
    let owner = listing.owner().map(str::to_owned);
    let owner_is_user = owner
        .as_deref()
        .is_none_or(|owner| vectispire_domain::java::compare_ignore_case(owner, &login) == std::cmp::Ordering::Equal);
    // By lower-case login: GitHub's logins are case-insensitive, and the owner is typed by a person.
    let mut organisations: Vec<(String, String)> = Vec::new();
    let add = |organisations: &mut Vec<(String, String)>, name: String| {
        let key = vectispire_domain::java::to_lower_root(&name);
        if !organisations.iter().any(|(known, _)| *known == key) {
            organisations.push((key, name));
        }
    };
    if !owner_is_user && let Some(owner) = owner {
        add(&mut organisations, owner);
    }
    if classic {
        for organisation in organisations_of(&pager, &api, listing).await? {
            add(&mut organisations, organisation);
        }
    }
    for (_, organisation) in organisations {
        listing.namespace(&organisation);
        let Some(segment) = path::segment(Some(&organisation)) else {
            listing.unreadable(&organisation, "GitHub named this organisation in a form no API path can carry.");
            continue;
        };
        github_walk(
            &pager,
            format!("{api}/orgs/{segment}/repos?type=all&sort=full_name&per_page=100"),
            &organisation,
            false,
            listing,
        )
        .await?;
    }
    if classic || owner_is_user {
        listing.namespace(&login);
        github_walk(&pager, format!("{api}{GITHUB_USER_REPOS}"), &login, true, listing).await?;
    }
    Ok(())
}

async fn organisations_of(
    pager: &OutboundPager,
    api: &str,
    listing: &mut impl Listing,
) -> Result<Vec<String>, ListError> {
    let mut found = Vec::new();
    let mut url = Some(format!("{api}{GITHUB_USER_ORGS}"));
    while let Some(current) = url {
        let answer = pager.get(&current).await?;
        match answer.status {
            200 => {}
            401 => return Err(github_rejected()),
            status => {
                listing.namespaces_incomplete(&format!(
                    "GitHub refused to list the organisations this token belongs to (HTTP {status} — a classic token \
                     needs read:org for it): only the connection's owner and the user's own repositories were listed."
                ));
                return Ok(found);
            }
        }
        if let Some(ids) = answer.header("x-github-sso").and_then(withheld_organisations) {
            listing.namespaces_incomplete(&format!(
                "GitHub left out {} {} (id {}) enforcing SAML single sign-on this token is not authorised for: \
                 authorise the token for each on GitHub, then discover again.",
                ids.len(),
                if ids.len() == 1 { "organisation" } else { "organisations" },
                ids.join(", ")
            ));
        }
        let next = pager.next(&answer, &current, NextPage::Link);
        let items = list_of(answer, || {
            ListError::Refused(
                DiscoveryReason::ForgeUnavailable,
                "GitHub answered the list of organisations with no list.".into(),
            )
        })?;
        found.extend(items.iter().filter_map(|organisation| text(Some(organisation), "login")));
        url = next;
    }
    Ok(found)
}

async fn github_walk(
    pager: &OutboundPager,
    first: String,
    namespace: &str,
    personal: bool,
    listing: &mut impl Listing,
) -> Result<(), ListError> {
    let mut url = Some(first);
    while let Some(current) = url {
        let answer = pager.get(&current).await?;
        match answer.status {
            200 => {}
            401 => return Err(github_rejected()),
            _ => {
                listing.unreadable(namespace, &github_refusal(&answer, personal));
                return Ok(());
            }
        }
        let next = pager.next(&answer, &current, NextPage::Link);
        let items = list_of(answer, || {
            ListError::Refused(
                DiscoveryReason::ForgeUnavailable,
                format!("GitHub answered the repositories of {namespace} with no list."),
            )
        })?;
        listing
            .repositories(items.iter().map(|repository| github_repository(repository, namespace, personal)).collect())
            .await?;
        url = next;
    }
    Ok(())
}

/// Why GitHub would not list an owner, in words an administrator can act on.
pub(crate) fn github_refusal(answer: &Answer, personal: bool) -> String {
    if answer.header("x-github-sso").is_some_and(|sso| {
        vectispire_domain::java::to_lower_root(vectispire_domain::java::trim(sso)).starts_with("required")
    }) {
        return "the organisation enforces SAML single sign-on and this token is not authorised for it (HTTP 403): \
                authorise the token for the organisation on GitHub, then discover again."
            .into();
    }
    match answer.status {
        403 => format!(
            "GitHub refused to list its repositories to this token (HTTP 403): an IP allow list, a policy refusing this \
             kind of token, or a token not granted {}",
            if personal { "the user's repositories." } else { "the organisation." }
        ),
        404 => format!(
            "GitHub shows no {} of that name to this token (HTTP 404): renamed, deleted, or a user rather than an \
             organisation.",
            if personal { "user" } else { "organisation" }
        ),
        status => format!("GitHub answered the listing with HTTP {status}."),
    }
}

/// The ids `X-GitHub-SSO: partial-results; organizations=1,2` says were left out.
pub(crate) fn withheld_organisations(header: &str) -> Option<Vec<String>> {
    let value = vectispire_domain::java::trim(header);
    if !vectispire_domain::java::to_lower_root(value).starts_with("partial-results") {
        return None;
    }
    let mut ids = Vec::new();
    for part in value.split(';') {
        let pair = vectispire_domain::java::trim(part);
        if vectispire_domain::java::to_lower_root(pair).starts_with("organizations=") {
            for id in pair.get("organizations=".len()..).unwrap_or_default().split(',') {
                let id = vectispire_domain::java::trim(id);
                if (1..=20).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_digit()) {
                    ids.push(id.to_owned());
                }
            }
        }
    }
    Some(if ids.is_empty() { vec!["unstated".to_owned()] } else { ids })
}

pub(crate) fn github_repository(repository: &Value, namespace: &str, personal: bool) -> DiscoveredRepository {
    let full_path = text(Some(repository), "full_name").unwrap_or_default();
    let owner = text(repository.get("owner"), "login").unwrap_or_else(|| {
        full_path.split_once('/').map_or_else(|| namespace.to_owned(), |(owner, _)| owner.to_owned())
    });
    let visibility = text(Some(repository), "visibility").or_else(|| {
        repository
            .get("private")
            .and_then(Value::as_bool)
            .map(|hidden| if hidden { "private" } else { "public" }.into())
    });
    DiscoveredRepository {
        forge_id: id_of(repository),
        full_path,
        namespace_path: owner,
        personal,
        name: text(Some(repository), "name").unwrap_or_default(),
        default_branch: text(Some(repository), "default_branch"),
        archived: flag(repository.get("archived")),
        fork: flag(repository.get("fork")),
        visibility,
        last_activity_at: instant(text(Some(repository), "pushed_at")),
        language: text(Some(repository), "language"),
        // Kibibytes.
        size_bytes: repository.get("size").and_then(Value::as_i64).and_then(|size| size.checked_mul(1024)),
        http_url: text(Some(repository), "clone_url"),
        ssh_url: text(Some(repository), "ssh_url"),
        web_url: text(Some(repository), "html_url"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_gitlab_project_leaves_unknown_what_gitlab_left_out() {
        let project = serde_json::json!({
            "id": 42, "path_with_namespace": "acme/backend/api", "name": "api",
            "namespace": {"full_path": "acme/backend", "kind": "group"},
            "default_branch": "main", "visibility": "private", "last_activity_at": "2026-09-01T10:00:00.000Z",
            "http_url_to_repo": "https://g/acme/backend/api.git"
        });
        let repository = gitlab_repository(&project);
        assert_eq!((repository.forge_id.as_str(), repository.namespace_path.as_str()), ("42", "acme/backend"));
        assert_eq!((repository.archived, repository.fork, repository.size_bytes), (None, None, None));
        assert_eq!(repository.last_activity_at, Instant::of_utc(2026, 9, 1, 10, 0, 0));
        let personal = gitlab_repository(&serde_json::json!({"id": 1, "path_with_namespace": "jdoe/x",
            "namespace": {"kind": "user"}, "forked_from_project": {}, "statistics": {"repository_size": 2048}}));
        assert_eq!((personal.personal, personal.namespace_path.as_str(), personal.fork), (true, "jdoe", Some(true)));
        assert_eq!(personal.size_bytes, Some(2048));
    }

    #[test]
    fn github_states_its_flags_and_its_size_in_kibibytes() {
        let repository = github_repository(
            &serde_json::json!({"id": 7, "full_name": "acme/api", "name": "api", "fork": false, "archived": true,
                "private": true, "size": 3, "pushed_at": "2026-09-01T10:00:00Z"}),
            "acme",
            false,
        );
        assert_eq!((repository.archived, repository.fork), (Some(true), Some(false)));
        assert_eq!((repository.visibility.as_deref(), repository.size_bytes), (Some("private"), Some(3072)));
        assert_eq!(repository.namespace_path, "acme");
    }

    #[test]
    fn the_main_language_and_the_withheld_organisations() {
        assert_eq!(main_language(Some(&serde_json::json!({"Java": 70.5, "Shell": 29.5}))).as_deref(), Some("Java"));
        assert_eq!(main_language(Some(&serde_json::json!({}))), None);
        assert_eq!(
            withheld_organisations("partial-results; organizations=12,x,34"),
            Some(vec!["12".into(), "34".into()])
        );
        assert_eq!(withheld_organisations("partial-results"), Some(vec!["unstated".into()]));
        assert_eq!(withheld_organisations("required; url=x"), None);
    }
}
