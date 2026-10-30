package com.asmolabs.vectispire.core.ai;

import com.asmolabs.vectispire.common.domain.aireview.AdviceLanguage;
import com.asmolabs.vectispire.common.domain.aireview.AiProvider;
import com.asmolabs.vectispire.common.domain.aireview.AiReview;
import com.asmolabs.vectispire.common.domain.aireview.AiVulnerabilityAdvice;
import com.asmolabs.vectispire.common.domain.crypto.SecretCipher;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.integrations.Integration;
import com.asmolabs.vectispire.common.domain.integrations.IntegrationDisabledException;
import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.threatintel.Exploitation;
import com.asmolabs.vectispire.core.crypto.EncryptionService;
import com.asmolabs.vectispire.core.crypto.SealedStore;
import com.asmolabs.vectispire.core.crypto.StoreCensus;
import com.asmolabs.vectispire.core.issues.IssueView;
import com.asmolabs.vectispire.core.outbound.OutboundJson;
import com.asmolabs.vectispire.core.outbound.OutboundPost;
import com.asmolabs.vectispire.core.settings.Integrations;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Code review by a model, through Ollama or an OpenAI-compatible API.
 *
 * <p><b>A light complement to the scanners, not a SAST engine</b>: one prompt against the
 * configured model, with no analysis chain. Off by default.
 *
 * <p><b>The model endpoint must stay internal, and that is the opposite of the webhook.</b> This
 * endpoint receives the <b>source code</b> of the scanned repository: the risk is not that it
 * points inward, it is that it points outward. An administrator — or somebody who phished one
 * — who aims it at their own server turns the review into an exfiltration channel, and a
 * well-formed public URL looks perfectly normal to an anti-SSRF guard. Hence {@link
 * OutboundPolicy#INTERNAL_REQUIRED}, and an explicit acknowledgement setting to open it.
 *
 * <p><b>That guard governs the URL, not the provider</b>, and deliberately so. Both providers are
 * held to the same rule: OpenAI's own address is public and therefore refused until the
 * acknowledgement is on, while an OpenAI-compatible server on the operator's own network — vLLM,
 * LM Studio, llama.cpp, an internal gateway — is reachable with it off, because nothing leaves.
 * Keying the rule on the provider name instead would have made "openai" mean "remote" even when
 * it points at localhost, and would have let a public Ollama through under a different name.
 *
 * <p><b>The provider is an integration the platform governor may switch off</b> (decision 0040 §3, lot I5),
 * and every call to a model leaves through {@code chat} or {@link #availableModels}, which ask the
 * registry first. Disabled, the features answer <em>AI unavailable — provider disabled</em> ({@link
 * #unavailable}) and <b>never the other provider</b>: the configured one is read once per call, and the
 * URL, the key and the request are that one's. A review moved without a word from the Ollama the operator
 * runs to OpenAI's hosted API would send the findings to a third party nobody chose for them — the reason
 * {@link AiProvider#of} falls back to Ollama, kept here in the other direction.
 */
@Service
public class AiReviewService implements SealedStore {

    private static final Logger log = LoggerFactory.getLogger(AiReviewService.class);

    private final SettingsService settings;
    private final OutboundJson get;
    private final OutboundPost post;
    private final ObjectMapper json;
    private final EncryptionService encryption;
    private final Integrations integrations;

    /** What every refusal of a disabled provider opens with: the reader asked for a report, not for a key. */
    public static final String UNAVAILABLE = "AI unavailable — provider disabled. Nothing is sent to the other "
            + "provider in its place.";

    /** Binds the stored key to its row, so a ciphertext moved elsewhere does not decrypt. */
    private static final String OPENAI_KEY_CONTEXT = "ai_review_openai_key";

    public AiReviewService(
            SettingsService settings,
            OutboundJson get,
            OutboundPost post,
            ObjectMapper json,
            EncryptionService encryption,
            Integrations integrations) {
        this.settings = settings;
        this.get = get;
        this.post = post;
        this.json = json;
        this.encryption = encryption;
        this.integrations = integrations;
    }

    /** Whether the configured provider's integration is on: what a screen asks before it offers a model's answer. */
    public boolean providerEnabled() {
        return integrations.isEnabled(Integration.of(provider()));
    }

    /**
     * Refuses when the configured provider is switched off — what a feature calls before it records or asks
     * anything, so that the refusal reaches the person who asked rather than a row they find later.
     *
     * @throws IntegrationDisabledException 409 {@code integration-disabled}, naming the provider, opened by
     *     {@link #UNAVAILABLE}
     */
    public void requireProviderEnabled() {
        requireEnabled(provider());
    }

    private void requireEnabled(AiProvider provider) {
        Integration integration = Integration.of(provider);
        if (!integrations.isEnabled(integration)) {
            throw unavailable(integration);
        }
    }

    /** The refusal of a feature whose provider is disabled: the integration's own, opened by {@link #UNAVAILABLE}. */
    public static IntegrationDisabledException unavailable(Integration provider) {
        return new IntegrationDisabledException(provider, UNAVAILABLE);
    }

    public boolean isEnabled() {
        return settings.isEnabled(Setting.AI_REVIEW_ENABLED);
    }

    /** Which API is spoken. Lenient on read: an unreadable value means Ollama — see {@link AiProvider}. */
    public AiProvider provider() {
        return AiProvider.of(settings.get(Setting.AI_REVIEW_PROVIDER));
    }

    public String ollamaUrl() {
        String configured = settings.get(Setting.AI_REVIEW_OLLAMA_URL).trim();
        return configured.isEmpty() ? AiReview.DEFAULT_OLLAMA_URL : configured;
    }

    public String openAiUrl() {
        String configured = settings.get(Setting.AI_REVIEW_OPENAI_URL).trim();
        return configured.isEmpty() ? AiReview.DEFAULT_OPENAI_URL : configured;
    }

    /** The endpoint in use, whichever provider is selected. */
    public String baseUrl() {
        return provider() == AiProvider.OPENAI ? openAiUrl() : ollamaUrl();
    }

    public boolean allowRemote() {
        return settings.isEnabled(Setting.AI_REVIEW_ALLOW_REMOTE);
    }

    public String selectedModel() {
        String configured = settings.get(Setting.AI_REVIEW_MODEL).trim();
        return configured.isEmpty() ? AiReview.DEFAULT_MODEL : configured;
    }

    /**
     * The validated URL, refusing a public destination by default.
     *
     * <p><b>Revalidated on every call</b>, not only when saved: this is where the source code
     * actually leaves the process, and the setting may have been written straight into the
     * database or may predate the guard.
     */
    public String validatedUrl() {
        return validatedUrl(provider());
    }

    /** This provider's URL — the one a call read once and holds to, never re-read halfway through it. */
    private String validatedUrl(AiProvider provider) {
        String url = provider == AiProvider.OPENAI ? openAiUrl() : ollamaUrl();
        if (!AiReview.isApiRoot(url)) {
            throw new InvalidInputException(
                    "The " + provider.wireName() + " URL carries a query or a fragment; it must be the API root alone.");
        }
        return trimTrailingSlashes(post.validate(url, policy(), provider.wireName() + " URL"));
    }

    /** Stores the URL after validating it — the entry point is where a mistake costs least. */
    public void setOllamaUrl(String url) {
        if (url == null || url.isBlank()) {
            throw new InvalidInputException("The Ollama service URL cannot be empty.");
        }
        Setting.AI_REVIEW_OLLAMA_URL.validate(url.trim()).ifPresent(problem -> {
            throw new InvalidInputException("Ollama URL — " + problem);
        });
        post.validate(url.trim(), policy(), "Ollama URL");
        settings.set(Setting.AI_REVIEW_OLLAMA_URL, url.trim());
    }

    /**
     * Stores the API key, encrypted.
     *
     * <p>Blank clears it, which is what a local endpoint authenticating nobody wants. Never read
     * back out to a screen: {@link #hasOpenAiKey()} answers the only question a form may ask.
     */
    public void setOpenAiKey(String rawKey) {
        String value = rawKey == null ? "" : rawKey.trim();
        settings.set(
                Setting.AI_REVIEW_OPENAI_KEY,
                value.isEmpty() ? "" : encryption.encrypt(value, OPENAI_KEY_CONTEXT));
    }

    /** Whether a key is stored, read without decrypting it — an undecryptable key is still one. */
    public boolean hasOpenAiKey() {
        return !settings.get(Setting.AI_REVIEW_OPENAI_KEY).trim().isEmpty();
    }

    /** Who accepted the data-leak risk, or empty when nobody has. */
    public String riskAcknowledgedBy() {
        return settings.get(Setting.AI_REVIEW_RISK_ACKNOWLEDGED_BY).trim();
    }

    /** When that acceptance was recorded, in UTC, or empty. */
    public String riskAcknowledgedAt() {
        return settings.get(Setting.AI_REVIEW_RISK_ACKNOWLEDGED_AT).trim();
    }

    /**
     * Records that somebody accepted the risk of sending code off-site, or erases the record.
     *
     * <p><b>Stamped by the server, from the authenticated principal and its own clock.</b> A
     * client-supplied name and date would be an acknowledgement the acknowledger writes about
     * themselves, which answers nothing an auditor asks. Erased when the switch goes back off, so
     * the row never claims an acceptance that no longer describes the configuration.
     */
    public void recordRiskAcknowledgement(String username, Instant at) {
        settings.set(Setting.AI_REVIEW_RISK_ACKNOWLEDGED_BY, username == null ? "" : username.trim());
        settings.set(Setting.AI_REVIEW_RISK_ACKNOWLEDGED_AT, at == null ? "" : at.toString());
    }

    public void clearRiskAcknowledgement() {
        settings.set(Setting.AI_REVIEW_RISK_ACKNOWLEDGED_BY, "");
        settings.set(Setting.AI_REVIEW_RISK_ACKNOWLEDGED_AT, "");
    }

    /**
     * Refuses a configuration that would send code off-site without the acceptance behind it.
     *
     * <p><b>Checked when the settings are saved, not only when a review runs.</b> The guard at call
     * time already refuses the request — but that refusal arrives minutes later, on another screen,
     * inside a scan whose report simply has no review in it. Somebody who pointed the URL at a
     * public host and left believes it is configured. This is the moment they are still looking at
     * the field.
     *
     * @param provider the provider the configuration will have once saved
     * @param url the endpoint that provider will use once saved
     * @param remoteAllowed whether the acknowledgement will be on once saved
     */
    public void requireLocalUnlessAcknowledged(AiProvider provider, String url, boolean remoteAllowed) {
        if (remoteAllowed) {
            return;
        }
        // The same guard the review itself is held to, run early. INTERNAL_REQUIRED resolves the
        // name and refuses a public address — so "looks internal" is never the test.
        post.validate(url, OutboundPolicy.INTERNAL_REQUIRED, provider.displayName() + " URL");
    }

    /**
     * The authentication headers for the selected provider.
     *
     * <p><b>An unreadable key sends nothing rather than sending the ciphertext.</b> The alternative
     * — passing whatever the column holds — puts an encrypted blob in an {@code Authorization}
     * header, where it fails as "invalid API key" and sends the operator to rotate a key that was
     * never the problem. Missing is diagnosable; wrong is not.
     */
    private Map<String, String> authentication(AiProvider provider) {
        if (provider != AiProvider.OPENAI) {
            return Map.of();
        }
        String stored = settings.get(Setting.AI_REVIEW_OPENAI_KEY).trim();
        if (stored.isEmpty()) {
            return Map.of();
        }
        SecretCipher.Decrypted key = encryption.inspect(stored, OPENAI_KEY_CONTEXT);
        if (key.state() == SecretCipher.SecretState.UNREADABLE) {
            log.error("The stored OpenAI key cannot be decrypted by any configured key — the request would go out "
                    + "unauthenticated and be refused. Set the API key again.");
            return Map.of();
        }
        return Map.of("Authorization", "Bearer " + key.plainText());
    }

    /**
     * The models actually installed on the configured host.
     *
     * <p><b>Never throws</b>: when Ollama is unreachable a short list of suggestions is
     * returned instead — never presented as installed, only as something reasonable to type
     * during setup.
     *
     * <p>A provider whose integration is disabled is not asked at all, and answers the suggestions too: the
     * advisor's status reads this for every signed-in account, and a list of models is not worth a request to
     * a host the governor switched off. The test button refuses before it gets here.
     */
    public List<String> availableModels() {
        AiProvider provider = provider();
        boolean openAi = provider == AiProvider.OPENAI;
        List<String> suggestions = openAi ? AiReview.OPENAI_MODEL_SUGGESTIONS : AiReview.FALLBACK_MODEL_SUGGESTIONS;
        if (!integrations.isEnabled(Integration.of(provider))) {
            return suggestions;
        }
        try {
            List<String> models = new ArrayList<>();
            // Two catalogues, two shapes: Ollama lists what is installed under `models[].name`,
            // OpenAI lists what the account may call under `data[].id`.
            get.get(validatedUrl(provider) + (openAi ? "/models" : "/api/tags"), policy(), provider.wireName(),
                            authentication(provider))
                    .ifPresent(payload -> {
                        for (JsonNode model : payload.path(openAi ? "data" : "models")) {
                            String name = model.path(openAi ? "id" : "name").asText("");
                            if (!name.isEmpty()) {
                                models.add(name);
                            }
                        }
                    });
            return models.isEmpty() ? suggestions : List.copyOf(models);
        } catch (RuntimeException unreachable) {
            log.warn("{} unreachable while listing models ({}) — suggestions returned.",
                    provider.wireName(), unreachable.getMessage());
            return suggestions;
        }
    }

    /**
     * Sends the code to the model and returns its raw answer.
     *
     * <p><b>Throws on failure</b>, unlike the configuration methods above: a caller that wanted
     * a review has to know it did not get one. Recording that on the result row rather than
     * failing the scan is the caller's decision, not this class's.
     */
    public String reviewCode(String code, String prompt) {
        return chat(List.of(
                Map.of("role", "system", "content", prompt),
                Map.of("role", "user", "content", AiReview.userMessage(code))));
    }

    /**
     * One exchange with the selected provider, returning the assistant's text.
     *
     * <p><b>The two protocols differ in three places and agree everywhere else</b>: the path, the
     * {@code stream} flag Ollama wants and OpenAI does not, and where the answer sits in the
     * response. Everything above this — the prompt, the delimiters, the parsing of findings — is
     * shared, because a review that meant something different depending on the provider would make
     * two products out of one feature.
     *
     * <p><b>The registry is asked here, on every call</b>, whoever the caller — a report asked from the button
     * or after a scan, an advice. The provider is read once and nothing below reads it again, so a provider
     * switched off is refused, never swapped for the other one.
     *
     * @throws IntegrationDisabledException when the configured provider is disabled, opened by {@link #UNAVAILABLE}
     */
    private String chat(List<Map<String, String>> messages) {
        AiProvider provider = provider();
        requireEnabled(provider);
        boolean openAi = provider == AiProvider.OPENAI;

        Map<String, Object> body = openAi
                ? Map.of("model", selectedModel(), "messages", messages)
                : Map.of("model", selectedModel(), "messages", messages, "stream", false);

        String response = post.postForResponse(
                validatedUrl(provider) + (openAi ? "/chat/completions" : "/api/chat"),
                body,
                policy(),
                provider.wireName(),
                authentication(provider),
                timeout());

        try {
            JsonNode root = json.readTree(response);
            // OpenAI returns a list of choices; Ollama returns the one message. Reading the wrong
            // shape yields "" — indistinguishable from a model that answered nothing — so each is
            // read where it actually is rather than by trying both.
            JsonNode content = openAi
                    ? root.path("choices").path(0).path("message").path("content")
                    : root.path("message").path("content");
            return content.asText("");
        } catch (JsonProcessingException notJson) {
            throw new IllegalStateException(
                    provider.wireName() + " answered with something that is not JSON", notJson);
        }
    }

    public String reviewCode(String code) {
        return reviewCode(code, AiReview.SECURITY_ARCHITECT_PROMPT);
    }

    /** How long to wait for the model. See the setting: the right value is a property of the host. */
    public java.time.Duration timeout() {
        int seconds = settings.asInt(Setting.AI_REVIEW_TIMEOUT_SECONDS);
        // A zero or a negative would mean "no timeout" to the HTTP client on some JDKs and throw
        // on others. The default is the honest reading of a value that cannot be a duration.
        return java.time.Duration.ofSeconds(seconds > 0 ? seconds : AiReview.DEFAULT_TIMEOUT_SECONDS);
    }

    /**
     * An issue explained by the model, or by this product when none answers.
     *
     * @param exploitation what the stored feeds say about it, resolved by the caller: the issue's
     *     own {@code isKev} reads false before the catalogue was ever read, and was sent to the
     *     model as {@code KEV: false} — a fact nobody had established
     * @param language the language the model is asked to answer in: the reader's
     * @throws IntegrationDisabledException with model review on and its provider disabled, opened by {@link
     *     #UNAVAILABLE}. Not the deterministic advice, which answers when review is off or a model failed: a
     *     reader who would have had the model's words would get this product's without being told why, and
     *     no screen could say the provider is off
     */
    public AiVulnerabilityAdvice explainVulnerability(
            IssueView issue, Exploitation exploitation, AdviceLanguage language) {
        String id = issue.identifier() != null ? issue.identifier() : "VULN-" + issue.id();
        String pkg = present(issue.packageName());
        String ver = present(issue.packageVersion());
        String fix = present(issue.fixVersions());

        if (isEnabled()) {
            requireProviderEnabled();
            try {
                // **`not_affected` is not among the choices offered, and that is deliberate.** The
                // model is told nothing about whether the code calls the package, because nothing
                // establishes it: no analysis writes the issue's reachability, which reads UNKNOWN
                // on every row. (A comment here said REACHABLE was written whenever a code finding
                // mentioned the package; nothing has written it since that correlation went.) A
                // model offered the `code_not_reachable` option produces a plausible and unfounded
                // exemption, which arrives pre-filled in front of a developer. Exempting stays a
                // person's decision; the model explains and proposes a fix.
                //
                // **An unknown is sent as "unknown", and the model is told not to fill it in.**
                // This sent `KEV: false` for a catalogue never read and `EPSS: null` for a CVE
                // nobody scored, and a model asked to explain fills a gap with a plausible figure.
                // The same six facts leave as before; only their spelling changed.
                //
                // **In the reader's language, not in French.** The prompt asked for French whoever
                // asked: an English reader got a French explanation beside the screen's English.
                // The language is the one the screen is shown in, English when none is given — no
                // account or instance setting names one.
                String prompt = String.format(
                        "Explain this vulnerability in %s for a developer: CVE: %s, Package: %s, Version: %s, Fixed: %s, KEV: %s, EPSS: %s. "
                                + "A value given as unknown is unknown: say so, and never estimate it. "
                                + "Nothing has established whether the application invokes the vulnerable code: say so in `exposure`, and say what to check, never that it is or is not invoked. "
                                + "Respond ONLY with valid JSON: {\"summary\":\"...\",\"mechanics\":\"...\",\"exposure\":\"...\",\"fix_action\":\"...\",\"cli_command\":\"...\",\"code_snippet\":\"...\",\"vex_status\":\"affected|under_investigation\",\"vex_statement\":\"...\"}",
                        language.englishName(), id, orUnknown(pkg), orUnknown(ver), orUnknown(fix),
                        kevFact(exploitation), epssFact(exploitation));

                String text = chat(List.of(
                        Map.of("role", "system", "content", "You are an AppSec assistant. Respond ONLY with valid JSON without markdown wrapping."),
                        Map.of("role", "user", "content", prompt)));
                if (text.startsWith("```")) {
                    text = text.replaceFirst("^```[a-zA-Z]*\\s*", "").replaceFirst("```\\s*$", "").trim();
                }
                JsonNode parsed = json.readTree(text);
                if (parsed != null && parsed.isObject()) {
                    return new AiVulnerabilityAdvice(
                            id,
                            "Model analysis for " + id + (pkg != null ? " (" + pkg + ")" : ""),
                            parsed.path("summary").asText(""),
                            parsed.path("mechanics").asText(""),
                            parsed.path("exposure").asText(""),
                            new AiVulnerabilityAdvice.RemediationAdvice(
                                    parsed.path("fix_action").asText(fix != null
                                            ? "Upgrade to " + fix + "."
                                            : "No fixed version is recorded for this vulnerability."),
                                    fix,
                                    parsed.path("code_snippet").asText(""),
                                    parsed.path("cli_command").asText("")),
                            new AiVulnerabilityAdvice.VexSuggestion(
                                    offeredStatus(parsed.path("vex_status").asText("")),
                                    // **No justification, whatever the model says.** This defaulted
                                    // to `vulnerable_code_cannot_be_controlled_by_adversary` — a
                                    // `not_affected` justification the prompt never asks for, so
                                    // every model advice carried it, and "apply the suggestion"
                                    // pre-filled it into the triage form.
                                    null,
                                    parsed.path("vex_statement").asText(""),
                                    fix != null
                                            ? "Apply the fix by upgrading to version " + fix + "."
                                            : "No fixed version is recorded: follow the advisory for a mitigation."),
                            AiVulnerabilityAdvice.references(issue.identifier()),
                            // Null on purpose: a model wrote the prose above, so there is nothing
                            // for a screen to rebuild — and pretending otherwise would have it
                            // render this product's words over the model's.
                            null);
                }
            } catch (IntegrationDisabledException switchedOff) {
                // Switched off between the question above and the call: the same refusal, never the fallback.
                throw switchedOff;
            } catch (Exception e) {
                log.info("Ollama inference not available or failed, falling back to deterministic advice: {}", e.getMessage());
            }
        }

        return AiVulnerabilityAdvice.generateDeterministic(id, pkg, ver, fix, present(issue.purl()), exploitation);
    }

    /**
     * The model's status if it is one the prompt offered, an investigation otherwise: a model that
     * answers {@code not_affected} anyway has produced the exemption the prompt withholds.
     */
    private static String offeredStatus(String answered) {
        return "affected".equals(answered) ? "affected" : "under_investigation";
    }

    private static String kevFact(Exploitation exploitation) {
        return switch (exploitation.kev()) {
            case LISTED -> "listed in the CISA KEV catalogue";
            case NOT_LISTED -> "not listed in the CISA KEV catalogue";
            case UNKNOWN -> "unknown";
        };
    }

    private static String epssFact(Exploitation exploitation) {
        return exploitation.epssScore() == null ? "unknown" : String.valueOf(exploitation.epssScore());
    }

    private static String orUnknown(String value) {
        return value == null ? "unknown" : value;
    }

    private static String present(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private OutboundPolicy policy() {
        return allowRemote() ? OutboundPolicy.INTERNAL_ALLOWED : OutboundPolicy.INTERNAL_REQUIRED;
    }

    private static String trimTrailingSlashes(String url) {
        return url.replaceAll("/+$", "");
    }

    @Override
    public List<StoreCensus> census() {
        return List.of(new StoreCensus.Counter("OpenAI API key", "set the key again on the model review settings")
                .add(encryption.sealOf(settings.get(Setting.AI_REVIEW_OPENAI_KEY), OPENAI_KEY_CONTEXT))
                .done());
    }
}
