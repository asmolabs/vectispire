package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.aireview.AiReview;
import com.asmolabs.zanshin.common.domain.aireview.AiVulnerabilityAdvice;
import com.asmolabs.zanshin.common.domain.net.OutboundPolicy;
import com.asmolabs.zanshin.common.domain.settings.Setting;
import com.asmolabs.zanshin.core.persistence.IssueEntity;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Code review by a local model, through Ollama.
 *
 * <p><b>A light complement to the scanners, not a SAST engine</b>: one prompt against the
 * configured model, with no analysis chain. Off by default.
 *
 * <p><b>The Ollama URL must stay internal, and that is the opposite of the webhook.</b> This
 * endpoint receives the <b>source code</b> of the scanned repository: the risk is not that it
 * points inward, it is that it points outward. An administrator — or somebody who phished one
 * — who aims it at their own server turns the review into an exfiltration channel, and a
 * well-formed public URL looks perfectly normal to an anti-SSRF guard. Hence {@link
 * OutboundPolicy#INTERNAL_REQUIRED}, and an explicit acknowledgement setting to open it.
 */
@Service
public class AiReviewService {

    private static final Logger log = LoggerFactory.getLogger(AiReviewService.class);

    private final SettingsService settings;
    private final OutboundJson get;
    private final OutboundPost post;
    private final ObjectMapper json;

    public AiReviewService(SettingsService settings, OutboundJson get, OutboundPost post, ObjectMapper json) {
        this.settings = settings;
        this.get = get;
        this.post = post;
        this.json = json;
    }

    public boolean isEnabled() {
        return settings.isEnabled(Setting.AI_REVIEW_ENABLED);
    }

    public String ollamaUrl() {
        String configured = settings.get(Setting.AI_REVIEW_OLLAMA_URL).trim();
        return configured.isEmpty() ? AiReview.DEFAULT_OLLAMA_URL : configured;
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
        return trimTrailingSlashes(post.validate(ollamaUrl(), policy(), "Ollama URL"));
    }

    /** Stores the URL after validating it — the entry point is where a mistake costs least. */
    public void setOllamaUrl(String url) {
        if (url == null || url.isBlank()) {
            throw new IllegalArgumentException("The Ollama service URL cannot be empty.");
        }
        post.validate(url.trim(), policy(), "Ollama URL");
        settings.set(Setting.AI_REVIEW_OLLAMA_URL, url.trim());
    }

    /**
     * The models actually installed on the configured host.
     *
     * <p><b>Never throws</b>: when Ollama is unreachable a short list of suggestions is
     * returned instead — never presented as installed, only as something reasonable to type
     * during setup.
     */
    public List<String> availableModels() {
        try {
            List<String> models = new ArrayList<>();
            get.get(validatedUrl() + "/api/tags", policy(), "Ollama").ifPresent(payload -> {
                for (JsonNode model : payload.path("models")) {
                    String name = model.path("name").asText("");
                    if (!name.isEmpty()) {
                        models.add(name);
                    }
                }
            });
            return models.isEmpty() ? AiReview.FALLBACK_MODEL_SUGGESTIONS : List.copyOf(models);
        } catch (RuntimeException unreachable) {
            log.warn("Ollama unreachable while listing models ({}) — suggestions returned.", unreachable.getMessage());
            return AiReview.FALLBACK_MODEL_SUGGESTIONS;
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
        String response = post.postForResponse(
                validatedUrl() + "/api/chat",
                Map.of(
                        "model", selectedModel(),
                        "messages", List.of(
                                Map.of("role", "system", "content", prompt),
                                Map.of("role", "user", "content", AiReview.userMessage(code))),
                        "stream", false),
                policy(),
                "Ollama",
                Map.of(),
                timeout());

        try {
            return json.readTree(response).path("message").path("content").asText("");
        } catch (JsonProcessingException notJson) {
            throw new IllegalStateException("Ollama answered with something that is not JSON", notJson);
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

    public AiVulnerabilityAdvice explainVulnerability(IssueEntity issue) {
        String id = issue.getIdentifier() != null ? issue.getIdentifier() : "VULN-" + issue.getId();
        String pkg = issue.getPackageName();
        String ver = issue.getPackageVersion();
        String fix = issue.getFixVersions();
        String reachability = issue.getReachability() != null ? issue.getReachability() : "UNKNOWN";
        boolean isKev = issue.isKev();
        Double epss = issue.getEpssScore();

        if (isEnabled()) {
            try {
                String prompt = String.format(
                        "Explain this vulnerability in French for a developer: CVE: %s, Package: %s, Version: %s, Fixed: %s, Reachability: %s, KEV: %s, EPSS: %s. Respond ONLY with valid JSON: {\"summary\":\"...\",\"mechanics\":\"...\",\"exposure\":\"...\",\"fix_action\":\"...\",\"cli_command\":\"...\",\"code_snippet\":\"...\",\"vex_status\":\"not_affected|affected|under_investigation\",\"vex_justification\":\"code_not_reachable|vulnerable_code_cannot_be_controlled_by_adversary\",\"vex_statement\":\"...\"}",
                        id, pkg, ver, fix, reachability, isKev, epss);

                String rawResponse = post.postForResponse(
                        validatedUrl() + "/api/chat",
                        Map.of(
                                "model", selectedModel(),
                                "messages", List.of(
                                        Map.of("role", "system", "content", "You are an AppSec assistant. Respond ONLY with valid JSON without markdown wrapping."),
                                        Map.of("role", "user", "content", prompt)),
                                "stream", false),
                        policy(),
                        "Ollama",
                        Map.of(),
                        timeout());

                JsonNode root = json.readTree(rawResponse).path("message").path("content");
                String text = root.asText("");
                if (text.startsWith("```")) {
                    text = text.replaceFirst("^```[a-zA-Z]*\\s*", "").replaceFirst("```\\s*$", "").trim();
                }
                JsonNode parsed = json.readTree(text);
                if (parsed != null && parsed.isObject()) {
                    return new AiVulnerabilityAdvice(
                            id,
                            "Analyse IA pour " + id + " (" + (pkg != null ? pkg : "composant") + ")",
                            parsed.path("summary").asText(""),
                            parsed.path("mechanics").asText(""),
                            parsed.path("exposure").asText(""),
                            new AiVulnerabilityAdvice.RemediationAdvice(
                                    parsed.path("fix_action").asText("Mettre à jour vers " + (fix != null ? fix : "la version corrigée")),
                                    fix != null ? fix : "version corrigée",
                                    parsed.path("code_snippet").asText(""),
                                    parsed.path("cli_command").asText("")),
                            new AiVulnerabilityAdvice.VexSuggestion(
                                    parsed.path("vex_status").asText("under_investigation"),
                                    parsed.path("vex_justification").asText("vulnerable_code_cannot_be_controlled_by_adversary"),
                                    parsed.path("vex_statement").asText(""),
                                    "Appliquer le patch correctif."),
                            List.of("https://nvd.nist.gov/vuln/detail/" + id, "https://www.first.org/epss"));
                }
            } catch (Exception e) {
                log.info("Ollama inference not available or failed, falling back to deterministic advice: {}", e.getMessage());
            }
        }

        return AiVulnerabilityAdvice.generateDeterministic(id, pkg, ver, fix, reachability, isKev, epss);
    }

    private OutboundPolicy policy() {
        return allowRemote() ? OutboundPolicy.INTERNAL_ALLOWED : OutboundPolicy.INTERNAL_REQUIRED;
    }

    private static String trimTrailingSlashes(String url) {
        return url.replaceAll("/+$", "");
    }
}
