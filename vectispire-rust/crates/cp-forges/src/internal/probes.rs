//! `ForgeProbes`, `GitLabClient` and `GitHubClient`: the probe of a connection's token, whatever its forge, with every
//! way it can fail turned into a [`ForgeConnectionRefusal`] — so the service decides on one type what is a security
//! event and what is not. **The guard's refusal is a security event, a network failure is not.**
//!
//! GitLab's probe is three requests — the token's own description (`/personal_access_tokens/self`), the server's
//! version, the user the token acts as — its scopes judged right after the first, before the token is presented
//! again. GitHub's is one, `GET /users/{owner}`, most of what it learns being in the headers.

use vectispire_cp_outbound::OutboundPolicy;
use vectispire_cp_outbound::json::{Answer, JsonError, OutboundJson, TIMEOUT};
use vectispire_cp_settings::IntegrationsError;
use vectispire_domain::forges::credential::{ForgeConnectionRefusal, ForgeCredential, RefusalReason};
use vectispire_domain::forges::{ForgeEdition, ForgeKind, expiry, version};
use vectispire_domain::instant::Instant;

use super::integrations::ForgeIntegrations;
use super::json;
use super::targets::ForgeTarget;

/// The REST version the GitHub adapters are written against.
pub(crate) const GITHUB_API_VERSION: &str = "2022-11-28";

/// What the forge said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Probe {
    pub credential: ForgeCredential,
    /// `None` when the forge reported no expiry.
    pub expires_at: Option<Instant>,
    /// `None` for the clouds, which state none, and when it could not be read.
    pub version: Option<String>,
}

/// Why a probe made no connection.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ProbeError {
    #[error(transparent)]
    Refused(#[from] ForgeConnectionRefusal),
    /// The forge's integration is disabled: nothing was sent, and nothing is recorded.
    #[error(transparent)]
    Disabled(#[from] IntegrationsError),
}

fn refused(reason: RefusalReason, message: impl Into<String>) -> ForgeConnectionRefusal {
    ForgeConnectionRefusal::new(reason, message)
}

#[derive(Clone, Debug)]
pub(crate) struct ForgeProbes {
    outbound: OutboundJson,
    integrations: ForgeIntegrations,
}

impl ForgeProbes {
    pub(crate) fn new(outbound: OutboundJson, integrations: ForgeIntegrations) -> ForgeProbes {
        ForgeProbes { outbound, integrations }
    }

    /// Presents the token to the forge — the only way a connection's token reaches a forge outside a discovery or a
    /// change-review reading, so the registry is asked here, whichever gesture called.
    pub(crate) async fn probe(&self, target: &ForgeTarget, token: &str) -> Result<Probe, ProbeError> {
        let kind = target.address.edition.kind();
        self.integrations.require_enabled(kind).await?;
        let probed = match kind {
            ForgeKind::Gitlab => self.gitlab(target, token).await,
            ForgeKind::Github => self.github(target, token).await,
        };
        probed.map_err(|failure| {
            ProbeError::Refused(match failure {
                Failed::Refused(refusal) => refusal,
                Failed::Outbound(JsonError::Unsafe(blocked)) => refused(
                    RefusalReason::DestinationBlocked,
                    format!(
                        "{}{}",
                        blocked.0,
                        if target.policy == OutboundPolicy::PublicOnly && !target.address.edition.cloud() {
                            " If this server is on your internal network, say so on the connection."
                        } else {
                            ""
                        }
                    ),
                ),
                Failed::Outbound(unreachable) => refused(RefusalReason::Unreachable, unreachable.to_string()),
            })
        })
    }

    async fn answer(
        &self,
        target: &ForgeTarget,
        url: &str,
        label: &str,
        headers: &[(&str, &str)],
    ) -> Result<Answer, Failed> {
        Ok(self.outbound.answer(url, target.policy, label, headers, target.sending(), TIMEOUT).await?)
    }

    async fn gitlab(&self, target: &ForgeTarget, token: &str) -> Result<Probe, Failed> {
        let api = &target.address.api_root;
        let headers = [("PRIVATE-TOKEN", token)];
        let label = format!("GitLab at {}", target.address.base_url);

        let answer = self.answer(target, &format!("{api}/personal_access_tokens/self"), &label, &headers).await?;
        let own = expect_gitlab(answer, "the token's description", target)?;
        let own = Some(&own);
        if !json::as_boolean(json::path(own, "active"), true) || json::as_boolean(json::path(own, "revoked"), false) {
            return Err(
                refused(RefusalReason::TokenRejected, "GitLab reports this token as revoked or inactive.").into()
            );
        }
        let scopes: Vec<String> =
            json::elements(own, "scopes").iter().map(|scope| json::as_text(Some(scope))).collect();
        // Judged now, before the token is presented again; the bot flag comes with the third answer.
        ForgeCredential::gitlab(scopes.iter().map(|scope| Some(scope.as_str())), false)?;
        let expires_at = json::text(own, "expires_at").and_then(|date| expiry::of_date(Some(date)));

        let answer = self.answer(target, &format!("{api}/version"), &label, &headers).await?;
        let versioned = expect_gitlab(answer, "its version", target)?;
        let found = json::text_value(json::path(Some(&versioned), "version"))
            .filter(|value| !vectispire_domain::java::is_blank(value))
            .map(str::to_owned);
        if let Some(found) = &found
            && version::too_old(target.address.edition, Some(found)) == Some(true)
        {
            return Err(refused(
                RefusalReason::VersionUnsupported,
                format!(
                    "This GitLab is version {found}; GitLab {} or later is required.",
                    version::GITLAB_MINIMUM_MAJOR
                ),
            )
            .into());
        }

        let answer = self.answer(target, &format!("{api}/user"), &label, &headers).await?;
        let user = expect_gitlab(answer, "the token's user", target)?;
        let bot = json::as_boolean(json::path(Some(&user), "bot"), false);
        Ok(Probe {
            credential: ForgeCredential::gitlab(scopes.iter().map(|scope| Some(scope.as_str())), bot)?,
            expires_at,
            version: found,
        })
    }

    async fn github(&self, target: &ForgeTarget, token: &str) -> Result<Probe, Failed> {
        let edition = target.address.edition;
        let owner = target.owner.as_deref();
        let Some(segment) = super::path::segment(owner) else {
            return Err(refused(
                RefusalReason::OwnerNotFound,
                format!("GitHub names no organisation or user \"{}\".", owner.unwrap_or("null")),
            )
            .into());
        };
        let authorization = format!("Bearer {token}");
        let answer = self
            .answer(
                target,
                &format!("{}/users/{segment}", target.address.api_root),
                &format!("{} at {}", edition.label(), target.address.base_url),
                &[("Authorization", &authorization), ("X-GitHub-Api-Version", GITHUB_API_VERSION)],
            )
            .await?;
        match answer.status {
            200 => {}
            401 => {
                return Err(refused(
                    RefusalReason::TokenRejected,
                    "GitHub rejected this token (HTTP 401): it is wrong, expired or revoked.",
                )
                .into());
            }
            404 => {
                return Err(refused(
                    RefusalReason::OwnerNotFound,
                    format!(
                        "GitHub knows no organisation or user \"{}\" visible with this token.",
                        owner.unwrap_or("null")
                    ),
                )
                .into());
            }
            // 403 is a rate limit, an organisation's SSO not yet authorised for the token, or an IP allow-list.
            status => {
                return Err(refused(
                    RefusalReason::Unreachable,
                    format!(
                        "GitHub answered HTTP {status}{}.",
                        if answer.header("x-github-sso").is_some() {
                            " — authorise the token for the organisation's single sign-on first"
                        } else {
                            ""
                        }
                    ),
                )
                .into());
            }
        }
        // The scopes first: a token broader than a connection may hold is the security event, whatever else is wrong.
        let credential = ForgeCredential::github(edition, answer.header("x-oauth-scopes"))?;
        let found =
            answer.header("x-github-enterprise-version").map(|value| vectispire_domain::java::trim(value).to_owned());
        if edition == ForgeEdition::GithubEnterpriseServer
            && let Some(found) = &found
            && version::too_old(edition, Some(found)) == Some(true)
        {
            return Err(refused(
                RefusalReason::VersionUnsupported,
                format!(
                    "This GitHub Enterprise Server is version {found}; {}.{} or later is required.",
                    version::GHES_MINIMUM_MAJOR,
                    version::GHES_MINIMUM_MINOR
                ),
            )
            .into());
        }
        Ok(Probe {
            credential,
            expires_at: expiry::of_github_header(answer.header("github-authentication-token-expiration")),
            version: if edition == ForgeEdition::GithubEnterpriseServer { found } else { None },
        })
    }
}

/// A probe's failure before it is turned into a refusal.
#[derive(Debug)]
enum Failed {
    Refused(ForgeConnectionRefusal),
    Outbound(JsonError),
}

impl From<ForgeConnectionRefusal> for Failed {
    fn from(refusal: ForgeConnectionRefusal) -> Failed {
        Failed::Refused(refusal)
    }
}

impl From<JsonError> for Failed {
    fn from(error: JsonError) -> Failed {
        Failed::Outbound(error)
    }
}

fn expect_gitlab(answer: Answer, what: &str, target: &ForgeTarget) -> Result<serde_json::Value, Failed> {
    match answer.status {
        200 => answer.body.ok_or_else(|| {
            refused(RefusalReason::Unreachable, format!("GitLab answered {what} with no document.")).into()
        }),
        401 => Err(refused(
            RefusalReason::TokenRejected,
            "GitLab rejected this token (HTTP 401): it is wrong, expired or revoked.",
        )
        .into()),
        403 => Err(refused(
            RefusalReason::ScopeMissing,
            format!("GitLab refused to answer {what} with this token (HTTP 403): it needs the read_api scope."),
        )
        .into()),
        // A server older than the token self-description (15.5) answers 404 to it.
        404 => Err(refused(
            RefusalReason::VersionUnsupported,
            format!(
                "GitLab at {} does not answer {what} (HTTP 404): it is not GitLab {} or later, or the address is not \
                 GitLab's web address.",
                target.address.base_url,
                version::GITLAB_MINIMUM_MAJOR
            ),
        )
        .into()),
        status => {
            Err(refused(RefusalReason::Unreachable, format!("GitLab answered {what} with HTTP {status}.")).into())
        }
    }
}
