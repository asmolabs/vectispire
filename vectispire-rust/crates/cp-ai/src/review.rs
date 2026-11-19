//! `AiReviewService`, the part the advisor reads: whether the model review is on, the provider and the model in use,
//! the models the provider lists, the chat call, and a vulnerability explained by the model or, failing it, by this
//! product.
//!
//! **The provider is an integration** (decision 0040, lot I5): switched off, an explanation answers 409
//! `integration-disabled`, "AI unavailable — provider disabled", and **the other provider is never asked in its
//! place** — choosing OpenAI is choosing to send data to a third party, and a fallback would make that choice for the
//! operator. **Unknown is said**: the prompt names a value nobody recorded as unknown, and asks the model not to
//! estimate it.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use vectispire_cp_crypto::{Encryption, SecretState};
use vectispire_cp_issues::views::IssueView;
use vectispire_cp_outbound::policy::OutboundPolicy;
use vectispire_cp_outbound::post::OutboundPost;
use vectispire_cp_settings::{Integrations, Setting, Settings};
use vectispire_cp_threatintel::status::{Exploitation, KevListing};
use vectispire_domain::integrations::Integration;
use vectispire_domain::java;

use crate::advice::{
    self, AdviceLanguage, AiVulnerabilityAdvice, Deterministic, RemediationAdvice, VexSuggestion, present,
};

/// `AiReviewService.UNAVAILABLE`: the refusal's lead, before the integration's own sentence.
pub const UNAVAILABLE: &str = "AI unavailable — provider disabled. Nothing is sent to the other provider in its place.";

/// `AiReview.DEFAULT_OLLAMA_URL`, `DEFAULT_OPENAI_URL`, `DEFAULT_MODEL`, `DEFAULT_TIMEOUT_SECONDS`.
pub const DEFAULT_OLLAMA_URL: &str = "http://localhost:11434";
pub const DEFAULT_OPENAI_URL: &str = "https://api.openai.com/v1";
pub const DEFAULT_MODEL: &str = "gemma4:12b-it-qat";
const DEFAULT_TIMEOUT_SECONDS: u64 = 300;

/// `AiReview.OPENAI_MODEL_SUGGESTIONS` and `FALLBACK_MODEL_SUGGESTIONS`: what the screen lists when the provider was
/// not asked, or did not answer.
const OPENAI_MODEL_SUGGESTIONS: [&str; 2] = ["gpt-4o-mini", "gpt-4o"];
const FALLBACK_MODEL_SUGGESTIONS: [&str; 2] = ["gemma4:12b-it-qat", "gemma4:e4b-it-qat"];

/// The OpenAI key's sealing context.
const OPENAI_KEY_CONTEXT: &str = "ai_review_openai_key";

/// `AiProvider`: a model on a machine the operator controls, or OpenAI's API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiProvider {
    Ollama,
    OpenAi,
}

impl AiProvider {
    /// `of`: the stored value read leniently — **unknown means Ollama**, the destination that leaks nothing.
    pub fn of(value: &str) -> AiProvider {
        if java::to_lower_root(java::trim(value)) == "openai" { AiProvider::OpenAi } else { AiProvider::Ollama }
    }

    pub fn wire_name(self) -> &'static str {
        match self {
            AiProvider::Ollama => "ollama",
            AiProvider::OpenAi => "openai",
        }
    }

    /// `Integration.of(provider)`.
    pub fn integration(self) -> Integration {
        let key = format!("ai.{}", self.wire_name());
        // Both keys are in `Integration::all` — `cp-settings`' tests hold the list.
        Integration::by_key(&key).unwrap_or_else(|| Integration::all().remove(0))
    }
}

/// Why an explanation, or the status, could not be given.
#[derive(Debug, thiserror::Error)]
pub enum ReviewError {
    /// The provider in use is switched off: 409 `integration-disabled`.
    #[error("{}", .0.disabled_message(UNAVAILABLE))]
    Disabled(Integration),
    /// The settings or the registry did not answer.
    #[error("{0}")]
    Failed(String),
}

/// A chat that produced nothing usable: the reason, for the log that says the advice fell back.
#[derive(Debug)]
enum ChatFailure {
    Disabled(Integration),
    Other(String),
}

/// The service.
#[derive(Clone)]
pub struct AiReviewService {
    settings: Settings,
    integrations: Arc<Integrations>,
    post: OutboundPost,
    encryption: Arc<Encryption>,
}

impl std::fmt::Debug for AiReviewService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("AiReviewService").finish_non_exhaustive()
    }
}

fn failed(error: impl std::fmt::Display) -> ReviewError {
    ReviewError::Failed(error.to_string())
}

impl AiReviewService {
    pub fn new(
        settings: Settings,
        integrations: Arc<Integrations>,
        post: OutboundPost,
        encryption: Arc<Encryption>,
    ) -> AiReviewService {
        AiReviewService { settings, integrations, post, encryption }
    }

    pub async fn is_enabled(&self) -> Result<bool, ReviewError> {
        self.settings.is_enabled(Setting::AiReviewEnabled).await.map_err(failed)
    }

    pub async fn provider(&self) -> Result<AiProvider, ReviewError> {
        Ok(AiProvider::of(&self.settings.get(Setting::AiReviewProvider).await.map_err(failed)?))
    }

    /// `providerEnabled`: the registry's word on the configured provider.
    pub async fn provider_enabled(&self) -> Result<bool, ReviewError> {
        let provider = self.provider().await?;
        self.integrations.is_enabled(provider.integration()).await.map_err(failed)
    }

    async fn require_enabled(&self, provider: AiProvider) -> Result<(), ChatFailure> {
        let integration = provider.integration();
        match self.integrations.is_enabled(integration).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(ChatFailure::Disabled(integration)),
            Err(failure) => Err(ChatFailure::Other(failure.to_string())),
        }
    }

    async fn configured(&self, setting: Setting, default: &str) -> Result<String, ReviewError> {
        let value = self.settings.get(setting).await.map_err(failed)?;
        let value = java::trim(&value);
        Ok(if value.is_empty() { default.to_owned() } else { value.to_owned() })
    }

    pub async fn selected_model(&self) -> Result<String, ReviewError> {
        self.configured(Setting::AiReviewModel, DEFAULT_MODEL).await
    }

    async fn url(&self, provider: AiProvider) -> Result<String, ReviewError> {
        match provider {
            AiProvider::OpenAi => self.configured(Setting::AiReviewOpenaiUrl, DEFAULT_OPENAI_URL).await,
            AiProvider::Ollama => self.configured(Setting::AiReviewOllamaUrl, DEFAULT_OLLAMA_URL).await,
        }
    }

    /// `policy`: an acknowledged remote destination is allowed; otherwise the model must sit inside the estate.
    async fn policy(&self) -> Result<OutboundPolicy, ReviewError> {
        let remote = self.settings.is_enabled(Setting::AiReviewAllowRemote).await.map_err(failed)?;
        Ok(if remote { OutboundPolicy::InternalAllowed } else { OutboundPolicy::InternalRequired })
    }

    /// `timeout`: the setting when positive, five minutes otherwise.
    async fn timeout(&self) -> Result<Duration, ReviewError> {
        let seconds = self.settings.as_int(Setting::AiReviewTimeoutSeconds).await.map_err(failed)?;
        Ok(Duration::from_secs(
            u64::try_from(seconds).ok().filter(|seconds| *seconds > 0).unwrap_or(DEFAULT_TIMEOUT_SECONDS),
        ))
    }

    /// `validatedUrl`: the API root alone — no query, no fragment — through the guard, trailing slashes dropped.
    async fn validated_url(&self, provider: AiProvider) -> Result<String, String> {
        let url = self.url(provider).await.map_err(|e| e.to_string())?;
        if url.contains('?') || url.contains('#') {
            return Err(format!(
                "The {} URL carries a query or a fragment; it must be the API root alone.",
                provider.wire_name()
            ));
        }
        let policy = self.policy().await.map_err(|e| e.to_string())?;
        let checked = self
            .post
            .validate(&url, policy, &format!("{} URL", provider.wire_name()))
            .await
            .map_err(|refused| refused.to_string())?;
        Ok(checked.trim_end_matches('/').to_owned())
    }

    /// `authentication`: OpenAI's key, opened; none for Ollama, none when unset, none — logged — when no key opens it.
    async fn authentication(&self, provider: AiProvider) -> Result<Vec<(String, String)>, String> {
        if provider != AiProvider::OpenAi {
            return Ok(Vec::new());
        }
        let stored = self.settings.get(Setting::AiReviewOpenaiKey).await.map_err(|e| e.to_string())?;
        let stored = java::trim(&stored);
        if stored.is_empty() {
            return Ok(Vec::new());
        }
        let key = self.encryption.inspect(stored, OPENAI_KEY_CONTEXT).await;
        if key.state() == SecretState::Unreadable {
            tracing::error!(
                "The stored OpenAI key cannot be decrypted by any configured key — the request would go out \
                 unauthenticated and be refused. Set the API key again."
            );
            return Ok(Vec::new());
        }
        Ok(vec![("Authorization".to_owned(), format!("Bearer {}", key.plain_text()))])
    }

    /// `availableModels`: the provider's own list when it is switched on and answers; the suggestions otherwise.
    pub async fn available_models(&self) -> Result<Vec<String>, ReviewError> {
        let provider = self.provider().await?;
        let open_ai = provider == AiProvider::OpenAi;
        let suggestions: Vec<String> =
            if open_ai { &OPENAI_MODEL_SUGGESTIONS[..] } else { &FALLBACK_MODEL_SUGGESTIONS[..] }
                .iter()
                .map(|model| (*model).to_owned())
                .collect();
        if !self.integrations.is_enabled(provider.integration()).await.map_err(failed)? {
            return Ok(suggestions);
        }
        match self.listed_models(provider).await {
            Ok(models) if !models.is_empty() => Ok(models),
            Ok(_) => Ok(suggestions),
            Err(unreachable) => {
                tracing::warn!(
                    "{} unreachable while listing models ({unreachable}) — suggestions returned.",
                    provider.wire_name()
                );
                Ok(suggestions)
            }
        }
    }

    async fn listed_models(&self, provider: AiProvider) -> Result<Vec<String>, String> {
        let open_ai = provider == AiProvider::OpenAi;
        let url = format!("{}{}", self.validated_url(provider).await?, if open_ai { "/models" } else { "/api/tags" });
        let policy = self.policy().await.map_err(|e| e.to_string())?;
        let headers = self.authentication(provider).await?;
        let Some(body) = self
            .post
            .get(&url, policy, provider.wire_name(), &headers, None)
            .await
            .map_err(|failure| failure.to_string())?
        else {
            return Ok(Vec::new());
        };
        let payload: Value =
            serde_json::from_str(&body).map_err(|unreadable| format!("{}: {unreadable}", provider.wire_name()))?;
        let (list, field) = if open_ai { ("data", "id") } else { ("models", "name") };
        Ok(payload
            .get(list)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|model| as_text(model.get(field), ""))
            .filter(|name| !name.is_empty())
            .collect())
    }

    /// `chat`: the provider in use, switched on, asked through the guard with its own timeout; the answer's content.
    async fn chat(&self, messages: Value) -> Result<String, ChatFailure> {
        let provider = self.provider().await.map_err(|e| ChatFailure::Other(e.to_string()))?;
        self.require_enabled(provider).await?;
        let open_ai = provider == AiProvider::OpenAi;
        let model = self.selected_model().await.map_err(|e| ChatFailure::Other(e.to_string()))?;
        let body = if open_ai {
            json!({"model": model, "messages": messages})
        } else {
            json!({"model": model, "messages": messages, "stream": false})
        };
        let other = ChatFailure::Other;
        let url = format!(
            "{}{}",
            self.validated_url(provider).await.map_err(other)?,
            if open_ai { "/chat/completions" } else { "/api/chat" }
        );
        let policy = self.policy().await.map_err(|e| other(e.to_string()))?;
        let headers = self.authentication(provider).await.map_err(other)?;
        let timeout = self.timeout().await.map_err(|e| other(e.to_string()))?;
        let response = self
            .post
            .post_for_response(&url, &body.to_string(), policy, provider.wire_name(), &headers, timeout)
            .await
            .map_err(|failure| other(failure.to_string()))?;
        let root: Value = serde_json::from_str(&response)
            .map_err(|_| other(format!("{} answered with something that is not JSON", provider.wire_name())))?;
        let content = if open_ai {
            root.get("choices").and_then(|choices| choices.get(0)).and_then(|choice| choice.get("message"))
        } else {
            root.get("message")
        }
        .and_then(|message| message.get("content"));
        Ok(as_text(content, ""))
    }

    /// `explainVulnerability`: the model's explanation when the review is on and the provider answers with the JSON it
    /// was asked for; this product's own otherwise. **Switched off, the provider is refused, not replaced**: 409.
    pub async fn explain_vulnerability(
        &self,
        issue: &IssueView,
        exploitation: Exploitation,
        language: AdviceLanguage,
    ) -> Result<AiVulnerabilityAdvice, ReviewError> {
        // An issue the scanner gave no identifier is stored empty: the `VULN-<id>` Java gives a null one.
        let identifier = Some(issue.identifier.as_str()).filter(|identifier| !identifier.is_empty());
        let id = identifier.map_or_else(|| format!("VULN-{}", issue.id), str::to_owned);
        let pkg = present(issue.package_name.as_deref());
        let version = present(issue.package_version.as_deref());
        let fix = present(issue.fix_versions.as_deref());
        if self.is_enabled().await? {
            let provider = self.provider().await?;
            match self.require_enabled(provider).await {
                Ok(()) => {}
                Err(ChatFailure::Disabled(integration)) => return Err(ReviewError::Disabled(integration)),
                Err(ChatFailure::Other(failure)) => return Err(ReviewError::Failed(failure)),
            }
            match self
                .modelled(&id, identifier, pkg.as_deref(), version.as_deref(), fix.as_deref(), exploitation, language)
                .await
            {
                Ok(Some(advice)) => return Ok(advice),
                Ok(None) => {}
                Err(ChatFailure::Disabled(integration)) => return Err(ReviewError::Disabled(integration)),
                Err(ChatFailure::Other(failure)) => tracing::info!(
                    "Ollama inference not available or failed, falling back to deterministic advice: {failure}"
                ),
            }
        }
        Ok(advice::generate_deterministic(
            Some(&id),
            pkg.as_deref(),
            version.as_deref(),
            fix.as_deref(),
            present(issue.purl.as_deref()).as_deref(),
            Some(exploitation),
        ))
    }

    /// The model's answer, read; none when it is not a JSON object.
    #[allow(clippy::too_many_arguments)]
    async fn modelled(
        &self,
        id: &str,
        identifier: Option<&str>,
        pkg: Option<&str>,
        version: Option<&str>,
        fix: Option<&str>,
        exploitation: Exploitation,
        language: AdviceLanguage,
    ) -> Result<Option<AiVulnerabilityAdvice>, ChatFailure> {
        let unknown = |value: Option<&str>| value.unwrap_or("unknown").to_owned();
        let prompt = format!(
            "Explain this vulnerability in {} for a developer: CVE: {id}, Package: {}, Version: {}, Fixed: {}, KEV: {}, \
             EPSS: {}. A value given as unknown is unknown: say so, and never estimate it. Nothing has established \
             whether the application invokes the vulnerable code: say so in `exposure`, and say what to check, never \
             that it is or is not invoked. Respond ONLY with valid JSON: {{\"summary\":\"...\",\"mechanics\":\"...\",\
             \"exposure\":\"...\",\"fix_action\":\"...\",\"cli_command\":\"...\",\"code_snippet\":\"...\",\
             \"vex_status\":\"affected|under_investigation\",\"vex_statement\":\"...\"}}",
            language.english_name(),
            unknown(pkg),
            unknown(version),
            unknown(fix),
            kev_fact(exploitation.kev),
            exploitation
                .epss_score
                .map_or_else(|| "unknown".to_owned(), vectispire_domain::wire::java_double_to_string),
        );
        let messages = json!([
            {"role": "system", "content": "You are an AppSec assistant. Respond ONLY with valid JSON without markdown wrapping."},
            {"role": "user", "content": prompt},
        ]);
        let mut text = self.chat(messages).await?;
        if text.starts_with("```") {
            text = unfenced(&text);
        }
        let parsed: Value =
            serde_json::from_str(&text).map_err(|unreadable| ChatFailure::Other(unreadable.to_string()))?;
        if !parsed.is_object() {
            return Ok(None);
        }
        let field = |name: &str, default: &str| as_text(parsed.get(name), default);
        let fix_default = match fix {
            Some(fix) => format!("Upgrade to {fix}."),
            None => "No fixed version is recorded for this vulnerability.".to_owned(),
        };
        let status = if field("vex_status", "") == "affected" { "affected" } else { "under_investigation" };
        Ok(Some(AiVulnerabilityAdvice {
            identifier: id.to_owned(),
            title: format!("Model analysis for {id}{}", pkg.map(|pkg| format!(" ({pkg})")).unwrap_or_default()),
            summary_explanation: field("summary", ""),
            exploit_mechanics: field("mechanics", ""),
            exposure_assessment: field("exposure", ""),
            remediation: RemediationAdvice {
                fix_action: field("fix_action", &fix_default),
                suggested_version: fix.map(str::to_owned),
                code_snippet_or_diff: field("code_snippet", ""),
                cli_command: field("cli_command", ""),
            },
            vex_suggestion: VexSuggestion {
                status: status.to_owned(),
                justification: None,
                impact_statement: field("vex_statement", ""),
                action_statement: match fix {
                    Some(fix) => format!("Apply the fix by upgrading to version {fix}."),
                    None => "No fixed version is recorded: follow the advisory for a mitigation.".to_owned(),
                },
            },
            references: advice::references(identifier),
            deterministic: None::<Deterministic>,
        }))
    }
}

/// The prompt's KEV fact.
fn kev_fact(kev: KevListing) -> &'static str {
    match kev {
        KevListing::Listed => "listed in the CISA KEV catalogue",
        KevListing::NotListed => "not listed in the CISA KEV catalogue",
        KevListing::Unknown => "unknown",
    }
}

/// `replaceFirst("^```[a-zA-Z]*\\s*", "").replaceFirst("```\\s*$", "").trim()`: the markdown fence models add despite
/// the instruction, stripped rather than argued with.
fn unfenced(text: &str) -> String {
    let after = text.strip_prefix("```").unwrap_or(text);
    let after = after.trim_start_matches(|c: char| c.is_ascii_alphabetic());
    let after = after.trim_start_matches(|c: char| regex_space(c));
    let body = match after.trim_end_matches(|c: char| regex_space(c)).strip_suffix("```") {
        Some(body) => body,
        None => after,
    };
    java::trim(body).to_owned()
}

/// `\\s` in a Java pattern: ASCII's six whitespace characters.
fn regex_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\u{0B}' | '\u{0C}' | '\r')
}

/// `JsonNode.asText(default)`: a value node's text, the default for an absent or null one, empty for a container.
fn as_text(node: Option<&Value>, default: &str) -> String {
    match node {
        None | Some(Value::Null) => default.to_owned(),
        Some(Value::String(text)) => text.clone(),
        Some(Value::Number(number)) => number.to_string(),
        Some(Value::Bool(flag)) => flag.to_string(),
        Some(Value::Array(_) | Value::Object(_)) => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_provider_is_ollama() {
        assert_eq!(AiProvider::of(" OpenAI "), AiProvider::OpenAi);
        assert_eq!(AiProvider::of("anthropic"), AiProvider::Ollama);
        assert_eq!(AiProvider::of(""), AiProvider::Ollama);
        assert_eq!(AiProvider::Ollama.integration().key(), "ai.ollama");
        assert_eq!(AiProvider::OpenAi.integration().key(), "ai.openai");
    }

    #[test]
    fn the_fence_is_stripped() {
        assert_eq!(unfenced("```json\n{\"a\":1}\n```"), "{\"a\":1}");
        assert_eq!(unfenced("```{\"a\":1}```  "), "{\"a\":1}");
        assert_eq!(unfenced("```\n{\"a\":1}"), "{\"a\":1}");
    }

    #[test]
    fn as_jackson_reads_text() {
        assert_eq!(as_text(Some(&json!("x")), "d"), "x");
        assert_eq!(as_text(Some(&json!(null)), "d"), "d");
        assert_eq!(as_text(None, "d"), "d");
        assert_eq!(as_text(Some(&json!(3)), "d"), "3");
        assert_eq!(as_text(Some(&json!({"a": 1})), "d"), "");
    }

    #[test]
    fn the_refusal_names_the_provider_and_the_route_that_enables_it() {
        assert_eq!(
            ReviewError::Disabled(AiProvider::Ollama.integration()).to_string(),
            "AI unavailable — provider disabled. Nothing is sent to the other provider in its place. The integration \
             \"ai.ollama\" is disabled on this installation; a platform governor enables it with PUT \
             /api/v1/integrations/ai.ollama/enabled."
        );
    }
}
