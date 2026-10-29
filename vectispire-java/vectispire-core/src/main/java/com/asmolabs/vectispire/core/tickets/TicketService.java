package com.asmolabs.vectispire.core.tickets;

import com.asmolabs.vectispire.common.domain.crypto.SecretCipher;
import com.asmolabs.vectispire.common.domain.forges.TokenExpiry;
import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.net.PinnedCa;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.tickets.TicketProvider;
import com.asmolabs.vectispire.common.domain.tickets.Tickets;
import com.asmolabs.vectispire.common.domain.tickets.Tickets.TicketableIssue;
import com.asmolabs.vectispire.core.crypto.EncryptionService;
import com.asmolabs.vectispire.core.crypto.SealedStore;
import com.asmolabs.vectispire.core.crypto.StoreCensus;
import com.asmolabs.vectispire.core.outbound.OutboundJson;
import com.asmolabs.vectispire.core.outbound.OutboundPost;
import com.asmolabs.vectispire.core.outbound.PinnedHttpSender;
import com.asmolabs.vectispire.core.outbound.PinnedHttpSender.Method;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
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
 *
 * <p><b>Every call to the tracker carries the CA pinned for it, when one is</b> ({@link Setting#TICKET_CA}):
 * the creations, the closures and the lookups they make first. A self-hosted tracker whose certificate
 * comes from the organisation's own CA failed every handshake against the runtime's store, so no ticket
 * was ever opened and the hourly sweep retried in silence. The pinned CA replaces that store for the
 * tracker, as a forge connection's does (decision 0037) — one call left on the runtime's store would fail
 * the same way, which is why the trust is read once per gesture and handed to each call.
 */
@Service
public class TicketService implements SealedStore {

    private static final Logger log = LoggerFactory.getLogger(TicketService.class);

    /** The token's encryption context, bound to its setting key. */
    public static final String TOKEN_CONTEXT = "setting:ticket_token";

    private final SettingsService settings;
    private final EncryptionService encryption;
    private final OutboundPost post;
    private final OutboundJson lookup;
    private final ObjectMapper json;
    private final Clock clock;
    private final TrackerTokenState tokenState;

    /** How the pinned CA's refusals name the field — the same rule as a forge's, in the tracker's words. */
    public static final PinnedCa.Subject CA = new PinnedCa.Subject("The tracker CA", "the tracker");

    public TicketService(
            SettingsService settings,
            EncryptionService encryption,
            OutboundPost post,
            OutboundJson lookup,
            ObjectMapper json,
            Clock clock,
            TrackerTokenState tokenState) {
        this.settings = settings;
        this.encryption = encryption;
        this.post = post;
        this.lookup = lookup;
        this.json = json;
        this.clock = clock;
        this.tokenState = tokenState;
    }

    /**
     * The CA an administrator is saving, read and checked as a forge connection's is: CA certificates only,
     * current now, within {@link PinnedCa#MAX_LENGTH}. Empty for a blank value, which clears the pin.
     *
     * @throws com.asmolabs.vectispire.common.domain.errors.InvalidInputException worded for whoever pasted it
     */
    public Optional<PinnedCa> caToPin(String pem) {
        return pem == null || pem.isBlank() ? Optional.empty() : Optional.of(PinnedCa.parsePasted(pem, clock.instant(), CA));
    }

    /**
     * What is pinned, for the screen: the first certificate's subject and the bundle's earliest expiry.
     *
     * @param subject null when the stored text no longer reads as a CA (a row edited by hand) — the
     *     calls refuse it, and the screen shows the field to replace
     */
    public record PinnedTrackerCa(String subject, Instant notAfter) {}

    /** Empty when nothing is pinned. Read without checking the dates: an expired CA is shown, to be replaced. */
    public Optional<PinnedTrackerCa> pinnedCa() {
        String stored = settings.get(Setting.TICKET_CA).trim();
        if (stored.isEmpty()) {
            return Optional.empty();
        }
        try {
            PinnedCa ca = PinnedCa.read(stored, CA);
            return Optional.of(new PinnedTrackerCa(ca.subject(), ca.notAfter()));
        } catch (RuntimeException unreadable) {
            return Optional.of(new PinnedTrackerCa(null, null));
        }
    }

    /**
     * The stored CA, checked current at every use as a forge's is: the JDK does not read a trust anchor's
     * own dates, and a lapsed CA must not vouch for the tracker.
     *
     * @throws com.asmolabs.vectispire.common.domain.errors.InvalidInputException when it no longer reads or
     *     is no longer valid — the gesture then fails, and says why, rather than falling back on the
     *     runtime's store
     */
    private Optional<PinnedCa> trust() {
        String stored = settings.get(Setting.TICKET_CA).trim();
        return stored.isEmpty() ? Optional.empty() : Optional.of(PinnedCa.parse(stored, clock.instant(), CA));
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

    /** What the stored webhook secret amounts to — three cases, because two of them refuse differently. */
    public sealed interface WebhookSecret {
        /** None set: the route accepts nothing, and says it is not configured. */
        record Absent() implements WebhookSecret {}

        /** Set, but no configured key decrypts it: the route refuses, as for a wrong signature. */
        record Unreadable() implements WebhookSecret {}

        record Present(String value) implements WebhookSecret {}
    }

    /**
     * The secret the tracker presents when it calls us.
     *
     * <p><b>Unreadable is not absent.</b> This went through the tolerant read the outbound token
     * uses, which answers an empty string for a value no key can decrypt — and an empty secret
     * meant "not enforced". A lost {@code ENCRYPTION_KEY}, a rotation that dropped the old one, or a
     * corrupted row therefore reopened the only anonymous mutating route to unsigned calls, while
     * the screen went on saying a secret was configured. The javadoc here claimed the opposite.
     */
    public WebhookSecret webhookSecret() {
        String stored = settings.get(Setting.TICKET_WEBHOOK_SECRET).trim();
        if (stored.isEmpty()) {
            return new WebhookSecret.Absent();
        }
        if (!EncryptionService.isCiphertext(stored)) {
            // Legacy clear value: still the secret, and readSecret says so at warn.
            return new WebhookSecret.Present(
                    encryption.readSecret(stored, WEBHOOK_SECRET_CONTEXT, "The inbound webhook secret"));
        }
        SecretCipher.Decrypted secret = encryption.inspect(stored, WEBHOOK_SECRET_CONTEXT);
        if (secret.state() == SecretCipher.SecretState.UNREADABLE) {
            log.error("The inbound webhook secret cannot be decrypted by any configured key — the ticket webhook "
                    + "refuses every call until it is set again.");
            return new WebhookSecret.Unreadable();
        }
        return new WebhookSecret.Present(secret.plainText());
    }

    /**
     * Whether the webhook will accept a correctly signed call, for a screen that must not show it.
     * An unreadable secret is not configured as far as that question goes: the screen said it was.
     */
    public boolean hasWebhookSecret() {
        return webhookSecret() instanceof WebhookSecret.Present;
    }

    /** Stores it encrypted. Blank clears it, which closes the webhook route. */
    public void setWebhookSecret(String rawSecret) {
        String value = rawSecret == null ? "" : rawSecret.trim();
        settings.set(
                Setting.TICKET_WEBHOOK_SECRET,
                value.isEmpty() ? "" : encryption.encrypt(value, WEBHOOK_SECRET_CONTEXT));
    }

    /**
     * Stores the token encrypted, bound to its own setting key — and forgets what was known of the previous one:
     * its expiry and a refusal describe a credential that is gone.
     */
    public void setToken(String rawToken) {
        String value = rawToken == null ? "" : rawToken.trim();
        settings.set(Setting.TICKET_TOKEN, value.isEmpty() ? "" : encryption.encrypt(value, TOKEN_CONTEXT));
        tokenState.reset();
    }

    /** How often the tracker is asked about its token: daily, like the forge connections' reading of theirs. */
    static final Duration TOKEN_CHECK_INTERVAL = Duration.ofDays(1);

    /**
     * What is known of the token, read from the tracker now when it can say — GitLab and GitHub report their
     * tokens' expiry — and announced when that changed something. Called when the token is saved.
     *
     * <p>Never throws, like the sweep: a tracker that does not answer leaves what was known as it was.
     */
    public TrackerTokenState.Health checkTokenNow() {
        Instant now = clock.instant();
        try {
            if (isEnabled()) {
                askTheTracker(now);
            }
            tokenState.announce(now);
        } catch (RuntimeException failed) {
            log.warn("The tracker token could not be checked: {}", failed.getMessage());
        }
        return tokenState.read();
    }

    /**
     * The daily check, from the hourly tick: the tracker is asked when it last answered a day ago or more, and
     * what there is to say is announced whatever it answered — an expiry entering its fourteen days changes no
     * stored value, only the date.
     */
    public void checkTokenIfDue() {
        Instant now = clock.instant();
        try {
            boolean due = tokenState.checkedAt().map(at -> !now.isBefore(at.plus(TOKEN_CHECK_INTERVAL))).orElse(true);
            if (isEnabled() && due) {
                askTheTracker(now);
            }
            tokenState.announce(now);
        } catch (RuntimeException failed) {
            log.warn("The tracker token could not be checked: {}", failed.getMessage());
        }
    }

    /** What the token's own state is, for the screen. */
    public TrackerTokenState.Health tokenHealth() {
        return tokenState.read();
    }

    /**
     * Asks GitLab or GitHub what they know of the token, through the same guard, policy and pinned CA as a
     * ticket. Jira and ServiceNow have no reliable way to say, and are not asked: their expiry is the one an
     * administrator declares, and a refusal is learned from the calls the sweep makes.
     */
    private void askTheTracker(Instant now) {
        TicketProvider provider = provider();
        if (provider != TicketProvider.GITLAB && provider != TicketProvider.GITHUB) {
            return;
        }
        String baseUrl = validatedBaseUrl(baseUrl());
        Optional<PinnedCa> trust = trust();
        OutboundJson.Answer answer = provider == TicketProvider.GITLAB
                // The token's own description: personal, group and project access tokens alike, as the forge
                // connections read theirs.
                ? lookup.answer(baseUrl + "/api/v4/personal_access_tokens/self", policy(), "GitLab",
                        Map.of("PRIVATE-TOKEN", token()), trust)
                // Any authenticated call carries the expiry in a header; the repository's is the one the
                // token must be able to read anyway.
                : lookup.answer(baseUrl + "/repos/" + githubRepository(), policy(), "GitHub",
                        Map.of("Authorization", "Bearer " + token(), "Accept", "application/vnd.github+json"), trust);
        switch (answer.status()) {
            case 200 -> {
                tokenState.recordReported(provider == TicketProvider.GITLAB
                        ? Optional.ofNullable(answer.body().orElseThrow().path("expires_at").textValue())
                                .flatMap(TokenExpiry::ofDate)
                        : answer.header("github-authentication-token-expiration").flatMap(TokenExpiry::ofGithubHeader),
                        now);
                // The tracker knows the token again — unless what refused it was a 403 on a ticket: describing
                // itself proves nothing about that permission, and clearing it here would have the refusal
                // announced again, and cleared again, every day.
                if (tokenState.read().refused().map(refusal -> refusal.status() != 403).orElse(true)) {
                    tokenState.recordAccepted(now);
                }
            }
            // Expired, revoked or wrong: the same answer every call of the sweep would get.
            case 401 -> tokenState.recordRefused(401, now);
            // A 403 here says the token may not describe itself or read the repository, not that it stopped
            // working; the sweep's own calls say whether it can still open a ticket.
            default -> log.warn("The tracker answered HTTP {} when asked about its token; nothing learned.",
                    answer.status());
        }
    }

    /** A call made with the token succeeded. Recorded apart, so that a failure to record never costs the ticket. */
    private void noteAccepted() {
        try {
            tokenState.recordAccepted(clock.instant());
        } catch (RuntimeException unrecorded) {
            log.warn("The tracker token's state could not be recorded: {}", unrecorded.getMessage());
        }
    }

    /**
     * A call failed: when the tracker refused the token — {@code 401}, or {@code 403} on a call the integration
     * needs — that is recorded, and announced once. The status is read from the failure's type, never its words.
     * A {@code 403} that is GitHub's rate limit is not a refusal: recording it would tell the administrator to
     * replace a token that works, and the next hour's sweep, once the limit resets, would clear it again.
     */
    private void noteFailure(RuntimeException failed) {
        if (failed instanceof OutboundJson.OutboundStatusException refused
                && !refused.rateLimited()
                && (refused.status() == 401 || refused.status() == 403)) {
            try {
                tokenState.recordRefused(refused.status(), clock.instant());
            } catch (RuntimeException unrecorded) {
                log.warn("The tracker token's state could not be recorded: {}", unrecorded.getMessage());
            }
        }
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
        Optional<PinnedCa> trust;
        try {
            // **Validated here too**, and not only when saved: a setting written straight into
            // the database must not become an unchecked destination.
            baseUrl = validatedBaseUrl(baseUrl());
            trust = trust();
        } catch (RuntimeException refused) {
            log.error("Ticket not created: {}", refused.getMessage());
            return Optional.empty();
        }

        try {
            String title = Tickets.title(issue, targetName);
            String body = Tickets.body(issue, targetName);
            Optional<Ticket> created = switch (provider()) {
                case GITLAB -> Optional.of(createGitlab(baseUrl, title, body, trust));
                case GITHUB -> Optional.of(createGithub(baseUrl, title, body, trust));
                case JIRA -> Optional.of(createJira(baseUrl, title, body, trust));
                case SERVICENOW -> Optional.of(createServiceNow(baseUrl, title, body, trust));
                case NONE -> Optional.empty();
            };
            if (created.isPresent()) {
                noteAccepted();
            }
            return created;
        } catch (RuntimeException failed) {
            noteFailure(failed);
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
        Optional<PinnedCa> trust;
        try {
            baseUrl = validatedBaseUrl(baseUrl());
            trust = trust();
        } catch (RuntimeException refused) {
            log.error("Ticket closure failed: {}", refused.getMessage());
            return false;
        }

        // Never the reference as typed: see Tickets.referencePath for what that let a person do with
        // the integration's token.
        Optional<String> segment = Tickets.referencePath(provider(), ticketRef, project());
        if (segment.isEmpty()) {
            log.warn("Ticket {} not closed: it is not a {} reference in project \"{}\".", ticketRef, provider(), project());
            return false;
        }

        try {
            switch (provider()) {
                case GITLAB -> closeGitlab(baseUrl, segment.get(), trust);
                case GITHUB -> closeGithub(baseUrl, segment.get(), trust);
                case JIRA -> closeJira(baseUrl, segment.get(), trust);
                case SERVICENOW -> closeServiceNow(baseUrl, segment.get(), resolutionReason, trust);
                case NONE -> {}
            }
            log.info("Successfully closed ticket {} on {}", ticketRef, provider());
            noteAccepted();
            return true;
        } catch (RuntimeException e) {
            noteFailure(e);
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

    private Ticket createGitlab(String baseUrl, String title, String body, Optional<PinnedCa> trust) {
        // The project identifier has to be encoded when it is a path ("group/project"), which is
        // the form most people have it in.
        String url = baseUrl + "/api/v4/projects/" + URLEncoder.encode(project(), StandardCharsets.UTF_8) + "/issues";
        JsonNode payload = read(post.send(
                Method.POST,
                url,
                Map.of("title", title, "description", body, "labels", String.join(",", labels())),
                policy(),
                "GitLab",
                Map.of("PRIVATE-TOKEN", token()),
                trust));

        return new Ticket("#" + payload.path("iid").asText(""), payload.path("web_url").asText(""));
    }

    private void closeGitlab(String baseUrl, String iid, Optional<PinnedCa> trust) {
        String url = baseUrl + "/api/v4/projects/" + URLEncoder.encode(project(), StandardCharsets.UTF_8) + "/issues/" + iid;
        // PUT: GitLab's "edit an issue". A POST on this path is not routed, so closing went out as one
        // and failed on every issue — see PinnedHttpSender.Method.
        post.send(Method.PUT, url, Map.of("state_event", "close"), policy(), "GitLab", Map.of("PRIVATE-TOKEN", token()),
                trust);
    }

    private Ticket createGithub(String baseUrl, String title, String body, Optional<PinnedCa> trust) {
        String url = baseUrl + "/repos/" + githubRepository() + "/issues";
        Map<String, Object> payload = new java.util.LinkedHashMap<>();
        payload.put("title", title);
        payload.put("body", body);
        if (!labels().isEmpty()) {
            payload.put("labels", labels());
        }

        JsonNode response = read(post.send(
                Method.POST,
                url,
                payload,
                policy(),
                "GitHub",
                Map.of("Authorization", "Bearer " + token(), "Accept", "application/vnd.github+json"),
                trust));

        return new Ticket("#" + response.path("number").asText(""), response.path("html_url").asText(""));
    }

    /**
     * The configured repository as a path, or a refusal the caller logs and survives.
     *
     * <p>Checked here as well as when saved: a value stored before the check, or written straight
     * into the database, must not steer the token's request either — see
     * {@link Tickets#githubRepositoryPath}.
     */
    private String githubRepository() {
        return Tickets.githubRepositoryPath(project()).orElseThrow(() -> new IllegalStateException(
                "the GitHub project \"" + project() + "\" is not an owner/repository pair"));
    }

    private void closeGithub(String baseUrl, String number, Optional<PinnedCa> trust) {
        String url = baseUrl + "/repos/" + githubRepository() + "/issues/" + number;
        // PATCH, the verb GitHub documents for "update an issue"; its tolerance of POST as an alias
        // is a legacy courtesy nothing here should lean on.
        post.send(
                Method.PATCH,
                url,
                Map.of("state", "closed", "state_reason", "completed"),
                policy(),
                "GitHub",
                Map.of("Authorization", "Bearer " + token(), "Accept", "application/vnd.github+json"),
                trust);
    }

    private Ticket createJira(String baseUrl, String title, String body, Optional<PinnedCa> trust) {
        Map<String, Object> fields = new java.util.LinkedHashMap<>();
        fields.put("project", Map.of("key", project()));
        fields.put("summary", title);
        fields.put("issuetype", Map.of("name", settings.get(Setting.TICKET_ISSUE_TYPE)));
        // Atlassian Document Format: Jira Cloud's v3 API refuses a plain string for `description`.
        fields.put("description", atlassianDocument(body));
        if (!labels().isEmpty()) {
            fields.put("labels", labels());
        }

        JsonNode payload = read(post.send(
                Method.POST,
                baseUrl + "/rest/api/3/issue",
                Map.of("fields", fields),
                policy(),
                "Jira",
                jiraHeaders(),
                trust));

        String key = payload.path("key").asText("");
        return new Ticket(key, key.isEmpty() ? "" : baseUrl + "/browse/" + key);
    }

    /**
     * Moves the issue to a "done" status, by the transition its own workflow offers.
     *
     * <p><b>The transition is asked for, not assumed.</b> It was the id {@code 31} — the "Done"
     * transition of one default Jira Cloud workflow. Transition ids belong to each project's
     * workflow, so elsewhere 31 was another transition, or none, and the close failed or moved the
     * issue somewhere unintended. Jira lists the transitions available to an issue with the status
     * each leads to; the one whose status is in the {@code done} category is the one to take.
     */
    private void closeJira(String baseUrl, String key, Optional<PinnedCa> trust) {
        String url = baseUrl + "/rest/api/3/issue/" + key + "/transitions";
        JsonNode offered = lookup.get(
                        url, policy(), "Jira", jiraHeaders(), PinnedHttpSender.DEFAULT_MAX_BODY_BYTES, trust)
                .orElseThrow(() -> new IllegalStateException("Jira lists no transitions for " + key + "."));
        String transition = null;
        for (JsonNode candidate : offered.path("transitions")) {
            if ("done".equals(candidate.path("to").path("statusCategory").path("key").asText())) {
                transition = candidate.path("id").asText("");
                break;
            }
        }
        if (transition == null || !transition.matches("[0-9]{1,10}")) {
            throw new IllegalStateException("No transition to a done status is available for " + key
                    + " in its workflow; it was left open.");
        }
        post.send(Method.POST, url, Map.of("transition", Map.of("id", transition)), policy(), "Jira", jiraHeaders(), trust);
    }

    private Ticket createServiceNow(String baseUrl, String title, String body, Optional<PinnedCa> trust) {
        String url = baseUrl + "/api/now/table/incident";
        Map<String, Object> payload = new java.util.LinkedHashMap<>();
        payload.put("short_description", title);
        payload.put("description", body);
        payload.put("category", "Security");
        payload.put("urgency", "1");
        payload.put("impact", "1");

        JsonNode response = read(post.send(Method.POST, url, payload, policy(), "ServiceNow", serviceNowHeaders(), trust));
        JsonNode result = response.path("result");
        String number = result.path("number").asText("");
        String sysId = result.path("sys_id").asText("");
        String webUrl = baseUrl + "/nav_to.do?uri=incident.do?sys_id=" + (sysId.isEmpty() ? number : sysId);
        return new Ticket(number.isEmpty() ? sysId : number, webUrl);
    }

    /**
     * Closes an incident, addressed by its {@code sys_id}.
     *
     * <p><b>The stored reference is usually not a {@code sys_id}.</b> Creation keeps the incident
     * number ({@code INC0012345}) because that is what people read, search and paste back — and what
     * {@code attachTicket} accepts from a person. The Table API addresses a record by {@code sys_id}
     * only, so a close sent to {@code /incident/INC0012345} found nothing, and no incident Vectispire
     * opened was ever closed by it. A number is therefore resolved first, by a query through the same
     * guard and pin, under the same policy.
     */
    private void closeServiceNow(String baseUrl, String incident, String resolutionReason, Optional<PinnedCa> trust) {
        String sysId = SERVICENOW_SYS_ID.matcher(incident).matches() ? incident : serviceNowSysId(baseUrl, incident, trust);
        String url = baseUrl + "/api/now/table/incident/" + sysId;
        post.send(
                Method.PATCH,
                url,
                Map.of("state", "6", "close_code", "Solved (Permanently)", "close_notes", "Resolved by Vectispire: " + resolutionReason),
                policy(),
                "ServiceNow",
                serviceNowHeaders(),
                trust);
    }

    /** A {@code sys_id} as ServiceNow issues one: 32 lower-case hex digits, nothing a path could carry. */
    private static final java.util.regex.Pattern SERVICENOW_SYS_ID = java.util.regex.Pattern.compile("[0-9a-f]{32}");

    /**
     * The {@code sys_id} of the incident with this number.
     *
     * <p><b>What comes back is checked before it becomes a path segment.</b> The reference was held
     * to its grammar so that nothing typed could steer a request made with the integration's token;
     * an answer pasted into the next URL unchecked would reopen that for whoever controls the
     * tracker's response.
     *
     * @param number already held to {@code Tickets.referencePath}'s grammar and encoded
     */
    private String serviceNowSysId(String baseUrl, String number, Optional<PinnedCa> trust) {
        String url = baseUrl + "/api/now/table/incident?sysparm_query="
                + URLEncoder.encode("number=" + number, StandardCharsets.UTF_8)
                + "&sysparm_fields=sys_id&sysparm_limit=1";
        JsonNode found = lookup.get(
                        url, policy(), "ServiceNow", serviceNowHeaders(), PinnedHttpSender.DEFAULT_MAX_BODY_BYTES, trust)
                .orElseThrow(() -> new IllegalStateException("ServiceNow does not know incident " + number + "."));
        String sysId = found.path("result").path(0).path("sys_id").asText("");
        if (!SERVICENOW_SYS_ID.matcher(sysId).matches()) {
            throw new IllegalStateException("ServiceNow returned no usable sys_id for incident " + number + ".");
        }
        return sysId;
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

    @Override
    public List<StoreCensus> census() {
        return List.of(
                new StoreCensus.Counter("Tracker access token", "set the token again on the ticketing settings")
                        .add(encryption.sealOf(settings.get(Setting.TICKET_TOKEN), TOKEN_CONTEXT))
                        .done(),
                new StoreCensus.Counter("Inbound tracker webhook secret",
                                "set the secret again on the ticketing settings, and in the tracker")
                        .add(encryption.sealOf(settings.get(Setting.TICKET_WEBHOOK_SECRET), WEBHOOK_SECRET_CONTEXT))
                        .done());
    }
}
