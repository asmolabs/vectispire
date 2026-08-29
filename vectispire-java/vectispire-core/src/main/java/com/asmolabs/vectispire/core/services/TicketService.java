package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.crypto.SecretCipher;
import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.tickets.TicketProvider;
import com.asmolabs.vectispire.common.domain.tickets.Tickets;
import com.asmolabs.vectispire.common.domain.tickets.Tickets.TicketableIssue;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Opening a ticket with GitLab or Jira.
 *
 * <p><b>The token is encrypted at rest.</b> It grants write access to the tracker, which is a
 * different class of secret from a webhook URL: it therefore goes through the encryption
 * service like an SSH key, instead of sitting in the clear in the settings table.
 *
 * <p><b>One ticket per issue, for its whole life.</b> Not per scan, and never reopened when the
 * issue comes back: a ticket that rises from the dead on every rescan is how people learn to
 * mute a project's notifications. The stored reference is set once and never cleared — it is
 * also the sweep's deduplication key.
 */
@Service
public class TicketService {

    private static final Logger log = LoggerFactory.getLogger(TicketService.class);

    /** The token's encryption context, bound to its setting key. */
    public static final String TOKEN_CONTEXT = "setting:ticket_token";

    private final SettingsService settings;
    private final EncryptionService encryption;
    private final OutboundPost post;
    private final ObjectMapper json;

    public TicketService(
            SettingsService settings, EncryptionService encryption, OutboundPost post, ObjectMapper json) {
        this.settings = settings;
        this.encryption = encryption;
        this.post = post;
        this.json = json;
    }

    /** @param reference what the tracker calls it; @param url where a human goes to read it */
    public record Ticket(String reference, String url) {}

    public TicketProvider provider() {
        return TicketProvider.fromWireName(settings.get(Setting.TICKET_PROVIDER)).orElse(TicketProvider.NONE);
    }

    public String baseUrl() {
        return trimTrailingSlashes(settings.get(Setting.TICKET_BASE_URL).trim());
    }

    public String project() {
        return settings.get(Setting.TICKET_PROJECT).trim();
    }

    public boolean isEnabled() {
        return provider().isEnabled() && !baseUrl().isEmpty() && !project().isEmpty() && !token().isEmpty();
    }

    /**
     * The decrypted token, or an empty string.
     *
     * <p><b>Never throws</b>: an undecryptable token — a rotated encryption key, say — must
     * disable ticket creation, not break the maintenance tick that calls this and that also
     * carries the purge and triage expiry.
     */
    public String token() {
        String stored = settings.get(Setting.TICKET_TOKEN).trim();
        if (stored.isEmpty()) {
            return stored;
        }

        // Tolerates a token written before this setting was encrypted — reported, never silent.
        // See EncryptionService.readSecret for why refusing it outright would disable the
        // integration rather than protect the row.
        return encryption.readSecret(stored, TOKEN_CONTEXT, "The tracker access token");
    }

    /** Binds the inbound webhook secret to its own row, like the token above. */
    public static final String WEBHOOK_SECRET_CONTEXT = "setting:ticket_webhook_secret";

    /**
     * The secret the tracker presents when it calls us, decrypted.
     *
     * <p>Read through the same tolerant path as the token: this one authenticates <b>the only
     * anonymous mutating route in the system</b>, so a value that stops being readable does not
     * fail closed in a way anybody notices — it makes the route refuse the real tracker, and a
     * triage decision simply stops arriving.
     */
    public String webhookSecret() {
        return encryption.readSecret(
                settings.get(Setting.TICKET_WEBHOOK_SECRET).trim(),
                WEBHOOK_SECRET_CONTEXT,
                "The inbound webhook secret");
    }

    /** Whether one is configured, for a screen that must not show it. */
    public boolean hasWebhookSecret() {
        return !settings.get(Setting.TICKET_WEBHOOK_SECRET).trim().isEmpty();
    }

    /** Stores it encrypted. Blank clears it, which leaves the webhook route anonymous. */
    public void setWebhookSecret(String rawSecret) {
        String value = rawSecret == null ? "" : rawSecret.trim();
        settings.set(
                Setting.TICKET_WEBHOOK_SECRET,
                value.isEmpty() ? "" : encryption.encrypt(value, WEBHOOK_SECRET_CONTEXT));
    }

    /** Stores the token encrypted, bound to its own setting key. */
    public void setToken(String rawToken) {
        String value = rawToken == null ? "" : rawToken.trim();
        settings.set(Setting.TICKET_TOKEN, value.isEmpty() ? "" : encryption.encrypt(value, TOKEN_CONTEXT));
    }

    /**
     * Opens a ticket. Empty on any failure, after logging it.
     *
     * <p>Never throws: this runs from the maintenance tick, and an unreachable tracker must not
     * stop the other jobs that share it.
     */
    public Optional<Ticket> createForIssue(TicketableIssue issue, String targetName) {
        if (!isEnabled()) {
            return Optional.empty();
        }

        String baseUrl;
        try {
            // **Validated here too**, and not only when saved: a setting written straight into
            // the database must not become an unchecked destination.
            baseUrl = validatedBaseUrl(baseUrl());
        } catch (RuntimeException refused) {
            log.error("Ticket not created: {}", refused.getMessage());
            return Optional.empty();
        }

        try {
            String title = Tickets.title(issue, targetName);
            String body = Tickets.body(issue, targetName);
            return switch (provider()) {
                case GITLAB -> Optional.of(createGitlab(baseUrl, title, body));
                case GITHUB -> Optional.of(createGithub(baseUrl, title, body));
                case JIRA -> Optional.of(createJira(baseUrl, title, body));
                case SERVICENOW -> Optional.of(createServiceNow(baseUrl, title, body));
                case NONE -> Optional.empty();
            };
        } catch (RuntimeException failed) {
            log.warn("Ticket creation failed for issue {} — will be retried: {}", issue.id(), failed.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Closes an existing ticket when an issue is verified resolved.
     */
    public boolean closeTicket(String ticketRef, String resolutionReason) {
        if (!isEnabled() || ticketRef == null || ticketRef.isBlank()) {
            return false;
        }

        String baseUrl;
        try {
            baseUrl = validatedBaseUrl(baseUrl());
        } catch (RuntimeException refused) {
            log.error("Ticket closure failed - invalid base URL: {}", refused.getMessage());
            return false;
        }

        try {
            switch (provider()) {
                case GITLAB -> closeGitlab(baseUrl, ticketRef, resolutionReason);
                case GITHUB -> closeGithub(baseUrl, ticketRef, resolutionReason);
                case JIRA -> closeJira(baseUrl, ticketRef, resolutionReason);
                case SERVICENOW -> closeServiceNow(baseUrl, ticketRef, resolutionReason);
                case NONE -> {}
            }
            log.info("Successfully closed ticket {} on {}", ticketRef, provider());
            return true;
        } catch (RuntimeException e) {
            log.warn("Failed to close ticket {} on {}: {}", ticketRef, provider(), e.getMessage());
            return false;
        }
    }

    /**
     * The base URL, validated.
     *
     * <p><b>Private is allowed by default here</b>, unlike the notification webhook: a
     * self-hosted GitLab or Jira commonly lives on an internal network. The setting remains, so
     * a deployment that only uses a hosted tracker can forbid it.
     */
    public String validatedBaseUrl(String url) {
        return trimTrailingSlashes(post.validate(url, policy(), "tracker URL"));
    }

    /**
     * The same policy for the base URL and for the call that follows it.
     *
     * <p>Read once and passed on rather than recomputed at each site: a base URL validated
     * under one policy and posted to under another would mean the check that ran is not the
     * check that applies.
     */
    private OutboundPolicy policy() {
        return settings.isEnabled(Setting.TICKET_ALLOW_PRIVATE_URL)
                ? OutboundPolicy.INTERNAL_ALLOWED
                : OutboundPolicy.PUBLIC_ONLY;
    }

    private List<String> labels() {
        return Tickets.parseLabels(settings.get(Setting.TICKET_LABELS));
    }

    private Ticket createGitlab(String baseUrl, String title, String body) {
        // The project identifier has to be encoded when it is a path ("group/project"), which is
        // the form most people have it in.
        String url = baseUrl + "/api/v4/projects/" + URLEncoder.encode(project(), StandardCharsets.UTF_8) + "/issues";
        JsonNode payload = read(post.postForResponse(
                url,
                Map.of("title", title, "description", body, "labels", String.join(",", labels())),
                policy(),
                "GitLab",
                Map.of("PRIVATE-TOKEN", token())));

        return new Ticket("#" + payload.path("iid").asText(""), payload.path("web_url").asText(""));
    }

    private void closeGitlab(String baseUrl, String ticketRef, String resolutionReason) {
        String iid = ticketRef.startsWith("#") ? ticketRef.substring(1) : ticketRef;
        String url = baseUrl + "/api/v4/projects/" + URLEncoder.encode(project(), StandardCharsets.UTF_8) + "/issues/" + iid;
        post.postForResponse(url, Map.of("state_event", "close"), policy(), "GitLab", Map.of("PRIVATE-TOKEN", token()));
    }

    private Ticket createGithub(String baseUrl, String title, String body) {
        String url = baseUrl + "/repos/" + project() + "/issues";
        Map<String, Object> payload = new java.util.LinkedHashMap<>();
        payload.put("title", title);
        payload.put("body", body);
        if (!labels().isEmpty()) {
            payload.put("labels", labels());
        }

        JsonNode response = read(post.postForResponse(
                url,
                payload,
                policy(),
                "GitHub",
                Map.of("Authorization", "Bearer " + token(), "Accept", "application/vnd.github+json")));

        return new Ticket("#" + response.path("number").asText(""), response.path("html_url").asText(""));
    }

    private void closeGithub(String baseUrl, String ticketRef, String resolutionReason) {
        String number = ticketRef.startsWith("#") ? ticketRef.substring(1) : ticketRef;
        String url = baseUrl + "/repos/" + project() + "/issues/" + number;
        post.postForResponse(
                url,
                Map.of("state", "closed", "state_reason", "completed"),
                policy(),
                "GitHub",
                Map.of("Authorization", "Bearer " + token(), "Accept", "application/vnd.github+json"));
    }

    private Ticket createJira(String baseUrl, String title, String body) {
        Map<String, Object> fields = new java.util.LinkedHashMap<>();
        fields.put("project", Map.of("key", project()));
        fields.put("summary", title);
        fields.put("issuetype", Map.of("name", settings.get(Setting.TICKET_ISSUE_TYPE)));
        // Atlassian Document Format: Jira Cloud's v3 API refuses a plain string for `description`.
        fields.put("description", atlassianDocument(body));
        if (!labels().isEmpty()) {
            fields.put("labels", labels());
        }

        JsonNode payload = read(post.postForResponse(
                baseUrl + "/rest/api/3/issue",
                Map.of("fields", fields),
                policy(),
                "Jira",
                jiraHeaders()));

        String key = payload.path("key").asText("");
        return new Ticket(key, key.isEmpty() ? "" : baseUrl + "/browse/" + key);
    }

    private void closeJira(String baseUrl, String ticketRef, String resolutionReason) {
        String url = baseUrl + "/rest/api/3/issue/" + ticketRef + "/transitions";
        // Default Jira Cloud transition or comment
        post.postForResponse(
                url,
                Map.of("transition", Map.of("id", "31")),
                policy(),
                "Jira",
                jiraHeaders());
    }

    private Ticket createServiceNow(String baseUrl, String title, String body) {
        String url = baseUrl + "/api/now/table/incident";
        Map<String, Object> payload = new java.util.LinkedHashMap<>();
        payload.put("short_description", title);
        payload.put("description", body);
        payload.put("category", "Security");
        payload.put("urgency", "1");
        payload.put("impact", "1");

        JsonNode response = read(post.postForResponse(url, payload, policy(), "ServiceNow", serviceNowHeaders()));
        JsonNode result = response.path("result");
        String number = result.path("number").asText("");
        String sysId = result.path("sys_id").asText("");
        String webUrl = baseUrl + "/nav_to.do?uri=incident.do?sys_id=" + (sysId.isEmpty() ? number : sysId);
        return new Ticket(number.isEmpty() ? sysId : number, webUrl);
    }

    private void closeServiceNow(String baseUrl, String ticketRef, String resolutionReason) {
        String url = baseUrl + "/api/now/table/incident/" + ticketRef;
        post.postForResponse(
                url,
                Map.of("state", "6", "close_code", "Solved (Permanently)", "close_notes", "Resolved by Vectispire: " + resolutionReason),
                policy(),
                "ServiceNow",
                serviceNowHeaders());
    }

    private Map<String, String> jiraHeaders() {
        Map<String, String> headers = new java.util.LinkedHashMap<>();
        headers.put("Accept", "application/json");
        String user = settings.get(Setting.TICKET_USER).trim();
        if (!user.isEmpty()) {
            String credentials = Base64.getEncoder()
                    .encodeToString((user + ":" + token()).getBytes(StandardCharsets.UTF_8));
            headers.put("Authorization", "Basic " + credentials);
        }
        return headers;
    }

    private Map<String, String> serviceNowHeaders() {
        Map<String, String> headers = new java.util.LinkedHashMap<>();
        headers.put("Accept", "application/json");
        String user = settings.get(Setting.TICKET_USER).trim();
        if (!user.isEmpty()) {
            String credentials = Base64.getEncoder()
                    .encodeToString((user + ":" + token()).getBytes(StandardCharsets.UTF_8));
            headers.put("Authorization", "Basic " + credentials);
        } else {
            headers.put("Authorization", "Bearer " + token());
        }
        return headers;
    }

    private static Map<String, Object> atlassianDocument(String body) {
        List<Object> paragraphs = new ArrayList<>();
        for (String line : body.split("\n")) {
            if (!line.isBlank()) {
                paragraphs.add(Map.of("type", "paragraph", "content", List.of(Map.of("type", "text", "text", line))));
            }
        }
        return Map.of("type", "doc", "version", 1, "content", paragraphs);
    }

    private JsonNode read(String response) {
        try {
            return json.readTree(response);
        } catch (JsonProcessingException notJson) {
            throw new IllegalStateException("The tracker answered with something that is not JSON", notJson);
        }
    }

    private static String trimTrailingSlashes(String url) {
        return url.replaceAll("/+$", "");
    }
}
