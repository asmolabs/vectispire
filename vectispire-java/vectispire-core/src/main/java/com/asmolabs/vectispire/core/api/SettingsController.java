package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.asmolabs.vectispire.common.domain.aireview.AiProvider;
import com.asmolabs.vectispire.common.domain.aireview.AiReview;
import com.asmolabs.vectispire.core.services.AiReviewService;
import com.asmolabs.vectispire.core.services.AuditLogService;
import com.asmolabs.vectispire.core.services.NotificationService;
import com.asmolabs.vectispire.core.services.SettingsService;
import com.asmolabs.vectispire.core.services.TicketService;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.RequiresAdministrator;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The settings, read by everybody and written by administrators.
 *
 * <p><b>The catalog decides everything.</b> A key that is not in it is refused on write, which
 * gives two properties at once: the screen does not have to know the list, and the settings
 * table cannot fill with keys no service reads — the exact state that makes an operator believe
 * they configured something.
 *
 * <p><b>Every write is audited</b>, like any administration action: moving the notification
 * threshold from high to critical changes what the organization sees, and that is the kind of
 * decision one wants to be able to date.
 */
@RestController
@RequestMapping("/api/v1/settings")
// The catalog is readable by any account — the screen needs the labels and the types — and the
// two writing routes narrow it to administrators. A method's own marker wins over the class's,
// which is what lets one controller carry two different rules without a second controller.
@RequiresAccount
public class SettingsController {

    private final SettingsService settings;
    private final TicketService tickets;
    private final AuditLogService audit;
    private final AiReviewService aiReview;
    private final NotificationService notifications;

    public SettingsController(
            SettingsService settings,
            TicketService tickets,
            AuditLogService audit,
            AiReviewService aiReview,
            NotificationService notifications) {
        this.settings = settings;
        this.tickets = tickets;
        this.audit = audit;
        this.aiReview = aiReview;
        this.notifications = notifications;
    }

    /**
     * @param value the effective value, default included — without it the screen would show an
     *     empty field where the service is applying something
     * @param defaultValue serialized as {@code default}, which is a Java keyword and therefore
     *     cannot be the field's name. The client reads {@code default}, and a settings screen
     *     whose every default is blank is what the mismatch looked like
     * @param configured told apart explicitly, because "never set" and "set to the same value as
     *     the default" do not read the same to an operator
     */
    public record SettingView(
            String key,
            String type,
            String section,
            String label,
            String help,
            @JsonProperty("default") String defaultValue,
            String value,
            boolean configured) {}

    public record Catalog(List<SettingView> settings) {}

    public record TokenRequest(String token) {}

    public record SecretRequest(String secret) {}

    /**
     * The catalog and the current values.
     *
     * <p>Both together rather than the values alone: the screen needs the type to pick its
     * control, and the help text to say what the setting does not do.
     */
    @GetMapping
    public Catalog list(@AuthenticationPrincipal VectispirePrincipal principal) {
        Map<String, String> stored = settings.stored();
        // **A sensitive setting's value only leaves for an administrator.** A webhook URL is a
        // bearer capability: whoever reads it can post in the channel where the team awaits
        // Vectispire's alerts. The catalog itself stays readable by everybody — the screen needs
        // the labels and the types.
        boolean isAdmin = principal.user()
                .flatMap(user -> Role.of(user.getRole()))
                .map(Role::isAdministrative)
                .orElse(false);

        List<SettingView> views = new ArrayList<>();
        for (Setting setting : Setting.values()) {
            views.add(new SettingView(
                    setting.key(),
                    setting.type().name().toLowerCase(java.util.Locale.ROOT),
                    // The label, not the enum constant. `Section` carries one and nothing called
                    // it, so every card on this screen was titled `model_review` and
                    // `end_of_life` — the raw name, lowercased, straight from the wire.
                    setting.section().label(),
                    setting.label(),
                    setting.help(),
                    setting.defaultValue(),
                    // **A credential's value leaves for nobody, an administrator included.** What
                    // is stored is a ciphertext; returning it puts the encrypted blob in a browser
                    // tab and a proxy log, and it is of no use to a form that cannot re-submit it
                    // anyway. The screens ask "is one configured" through the route that owns it.
                    setting.isEncrypted() || (setting.isSecret() && !isAdmin)
                            ? null
                            : stored.getOrDefault(setting.key(), setting.defaultValue()),
                    stored.containsKey(setting.key())));
        }
        return new Catalog(views);
    }

    @org.springframework.security.access.prepost.PreAuthorize("hasAnyRole('SUPERUSER', 'ADMIN', 'CISO')")
    @PutMapping
    public Map<String, Integer> update(
            @RequestBody Map<String, String> body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        if (body == null || body.isEmpty()) {
            throw new IllegalArgumentException("No setting supplied.");
        }

        record Change(Setting setting, String value) {}
        List<Change> changes = new ArrayList<>();
        for (Map.Entry<String, String> entry : body.entrySet()) {
            Setting setting = Setting.byKey(entry.getKey())
                    .orElseThrow(() -> new IllegalArgumentException("Unknown setting: \"" + entry.getKey() + "\"."));
            String value = entry.getValue() == null ? "" : entry.getValue().trim();
            // **The acceptance record is written by this server or not at all.** It is in the
            // catalog so a screen can display it; accepting it on the wire would let the person
            // who opened the public endpoint also choose whose name and date sit against that
            // decision, which is the one thing the record exists to prevent.
            if (setting == Setting.AI_REVIEW_RISK_ACKNOWLEDGED_BY
                    || setting == Setting.AI_REVIEW_RISK_ACKNOWLEDGED_AT) {
                throw new IllegalArgumentException(
                        setting.label() + " is recorded by the server when the public endpoint is turned on, "
                                + "and cannot be set here.");
            }
            // **A credential has one door, and this is not it.** Each of these has a route that
            // encrypts the value before it reaches the database; this path stores what it is
            // handed. Left open, it wrote tracker tokens, webhook secrets and provider keys in the
            // clear — 200 OK, no warning — and the audit description below would then have carried
            // the value itself into a log that is deliberately never purged.
            if (setting.isEncrypted()) {
                throw new IllegalArgumentException(
                        setting.label() + " is a credential and is written by its own route, which encrypts it. "
                                + "Setting it here would store it in the clear.");
            }
            setting.validate(value).ifPresent(problem -> {
                throw new IllegalArgumentException(setting.label() + " — " + problem);
            });
            changes.add(new Change(setting, value));
        }

        // **The AI destination is checked against the state this save will produce**, not the one
        // in the database now: half of it may be in this very request. Done before any write, like
        // every other validation here — a refusal has to leave the configuration untouched.
        Map<Setting, String> pending = new java.util.EnumMap<>(Setting.class);
        changes.forEach(change -> pending.put(change.setting(), change.value()));
        String previousAcknowledgement = settings.get(Setting.AI_REVIEW_ALLOW_REMOTE);
        boolean remoteAfter = "true".equals(
                pending.getOrDefault(Setting.AI_REVIEW_ALLOW_REMOTE, previousAcknowledgement));
        AiProvider providerAfter = AiProvider.of(
                pending.getOrDefault(Setting.AI_REVIEW_PROVIDER, settings.get(Setting.AI_REVIEW_PROVIDER)));
        String urlAfter = providerAfter == AiProvider.OPENAI
                ? pending.getOrDefault(Setting.AI_REVIEW_OPENAI_URL, aiReview.openAiUrl())
                : pending.getOrDefault(Setting.AI_REVIEW_OLLAMA_URL, aiReview.ollamaUrl());
        if (urlAfter.isBlank()) {
            urlAfter = providerAfter == AiProvider.OPENAI ? AiReview.DEFAULT_OPENAI_URL : AiReview.DEFAULT_OLLAMA_URL;
        }

        // **A save that takes the acknowledgement away is never refused.** The check below asks
        // whether the resulting configuration may send code off-site, and answers by refusing a
        // public destination — which meant that switching the acknowledgement off while the
        // provider was still `openai` produced a 422 naming a URL the operator had not touched.
        // The only way out was to send both changes at once, and nothing said so. A guard that
        // stops the configuration from becoming *safer* is pointing the wrong way.
        //
        // Letting it through costs nothing: `validatedUrl()` runs the same guard on every single
        // review, so `openai` with the acknowledgement off simply sends nowhere. The refusal was
        // buying a state that the review path already refused.
        boolean withdrawsAcknowledgement = !remoteAfter && "true".equals(previousAcknowledgement);
        if (!withdrawsAcknowledgement) {
            aiReview.requireLocalUnlessAcknowledged(providerAfter, urlAfter, remoteAfter);
        }

        // All validated before any is written: a partial write would leave the configuration
        // half-way between two intended states.
        changes.forEach(change -> settings.set(change.setting(), change.value()));

        // **The acceptance is stamped here, by the server, or erased here.** Recorded after the
        // write so it describes a configuration that exists, and only on the transition — saving
        // an unrelated setting while the switch is already on must not rewrite whose decision it
        // was, or the record would name whoever edited the screen last.
        if (pending.containsKey(Setting.AI_REVIEW_ALLOW_REMOTE)
                && !pending.get(Setting.AI_REVIEW_ALLOW_REMOTE).equals(previousAcknowledgement)) {
            if (remoteAfter) {
                aiReview.recordRiskAcknowledgement(
                        principal.user().map(user -> user.getUsername()).orElse(""), Instant.now());
            } else {
                aiReview.clearRiskAcknowledgement();
            }
        }

        audit.record(new AuditLogService.Record(
                AuditOperation.SETTING_UPDATED,
                changes.stream().map(change -> change.setting().key()).reduce((a, b) -> a + "," + b).orElse(""),
                changes.stream()
                        .map(change -> {
                            if (change.setting() == Setting.FOUR_EYES_APPROVAL_REQUIRED) {
                                return "Double validation (Four-Eyes Approval) for VEX triage set to " 
                                        + ("true".equalsIgnoreCase(change.value()) ? "ENABLED" : "DISABLED");
                            }
                            return change.setting().key() + " = " + (change.value().isEmpty() ? "(empty)" : change.value());
                        })
                        .reduce((a, b) -> a + "; " + b)
                        .orElse(""),
                principal.user().map(user -> user.getUsername()).orElse(null),
                request.getRemoteAddr(),
                request.getHeader("User-Agent")));

        return Map.of("updated", changes.size());
    }

    /**
     * The tracker token, write-only.
     *
     * <p><b>Its own route, outside the catalog</b>, because a secret does not behave like a
     * setting: it is encrypted at rest, it cannot be read back into a form, and the screen can
     * therefore only show "configured" or "absent". Routing it through the generic path would
     * have needed an exception at every step — read, validate, audit — and one of them would
     * eventually have been forgotten.
     */
    @RequiresAdministrator
    @PutMapping("/ticket-token")
    public Map<String, Boolean> setTicketToken(
            @RequestBody TokenRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        String token = body == null || body.token() == null ? "" : body.token();
        tickets.setToken(token);

        audit.record(new AuditLogService.Record(
                AuditOperation.SETTING_UPDATED,
                Setting.TICKET_TOKEN.key(),
                // The value is **not** logged, unlike the other settings: the audit trail is
                // readable by every administrator.
                token.isBlank() ? "Tracker token cleared." : "Tracker token stored.",
                principal.user().map(user -> user.getUsername()).orElse(null),
                request.getRemoteAddr(),
                request.getHeader("User-Agent")));

        return Map.of("configured", !token.isBlank());
    }

    /** The token's state, without ever returning it. */
    @GetMapping("/ticket-token")
    public Map<String, Boolean> ticketTokenState() {
        return Map.of("configured", !tickets.token().isEmpty());
    }

    /**
     * The webhook signing secret, stored and never read back.
     *
     * <p>Its own route for the same reasons as the tracker token above: encrypted at rest, not
     * renderable into a form, and an exception at every step of the generic path is an exception
     * somebody eventually forgets.
     */
    @RequiresAdministrator
    @PutMapping("/webhook-secret")
    public Map<String, Boolean> setWebhookSigningSecret(
            @RequestBody SecretRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        String secret = body == null || body.secret() == null ? "" : body.secret();
        notifications.setSigningSecret(secret);

        audit.record(new AuditLogService.Record(
                AuditOperation.SETTING_UPDATED,
                Setting.WEBHOOK_SIGNING_SECRET.key(),
                // Never the value. Whoever reads this table could otherwise forge a message into
                // every channel this deployment announces to — and the audit log is deliberately
                // never purged, so it would outlive the secret's own rotation.
                secret.isBlank()
                        ? "Webhook signing secret cleared — messages are sent unsigned."
                        : "Webhook signing secret stored — messages are signed.",
                principal.user().map(user -> user.getUsername()).orElse(null),
                request.getRemoteAddr(),
                request.getHeader("User-Agent")));

        return Map.of("configured", !secret.isBlank());
    }

    /**
     * Whether messages are signed.
     *
     * <p>Reads the stored row rather than decrypting it: an undecryptable secret is still a
     * configured one, and this screen must say "signing" where the delivery will say why it
     * cannot — reporting "not configured" here would send an operator to set it again, which is
     * the one action that destroys the secret their receivers still hold.
     */
    @GetMapping("/webhook-secret")
    public Map<String, Boolean> webhookSigningSecretState() {
        return Map.of("configured", notifications.isSigning());
    }

    /**
     * @param reachable whether the host answered at all
     * @param modelInstalled whether the configured model is among the ones it holds. <b>Separate
     *     from {@code reachable} deliberately</b>: a reachable Ollama without the model is the
     *     most common way this is misconfigured, and a single green tick would hide it until the
     *     first report failed
     * @param detail what to do about it, in a sentence, because a boolean pair is a puzzle
     */
    public record OllamaCheck(
            boolean reachable,
            boolean modelInstalled,
            String model,
            String url,
            List<String> models,
            String detail,
            String provider,
            // **Not "the code left the estate" — "a destination outside it is permitted".** Whether
            // this URL actually resolves outside is the guard's answer, made per request; claiming
            // more than that here would be a badge that is wrong in both directions.
            boolean remoteAllowed) {}

    /**
     * Asks the configured Ollama what it holds.
     *
     * <p><b>A test button exists because the alternative is finding out from a failed report.</b>
     * Every part of this configuration — the URL, whether a remote one is allowed, the model's
     * name — is only exercised when something asks for a review, which is minutes later and on
     * another screen. The check runs the same URL validation as a real call, so a refusal here is
     * the refusal a report would get.
     *
     * <p>It reports rather than throws: "unreachable" is an answer to the question the button
     * asks, not an error in asking it.
     *
     * <p><b>Narrowed to whoever may configure the endpoint</b>, which is the same set as the route
     * that writes it rather than the narrower administrator marker — testing a field one is
     * allowed to edit should not need a second account. Under the class marker alone it was
     * reachable by any signed-in reader, and it answers with the configured URL: the one value
     * `ai_review_ollama_url` is marked {@code SECRET} to keep out of exactly those hands, since an
     * internal model endpoint describes the estate's topology. It also makes the server open an
     * outbound connection on the caller's say-so, which is not a reader's to spend.
     */
    @org.springframework.security.access.prepost.PreAuthorize("hasAnyRole('SUPERUSER', 'ADMIN', 'CISO')")
    @PostMapping("/ollama-test")
    public OllamaCheck testOllama() {
        String model = aiReview.selectedModel();
        AiProvider provider = aiReview.provider();
        // Two forms on purpose: `name` goes into sentences a person reads, `wireName` into the
        // field a client compares against.
        String name = provider.displayName();
        boolean remoteAllowed = aiReview.allowRemote();
        String url;
        try {
            url = aiReview.validatedUrl();
        } catch (RuntimeException refused) {
            // A public URL with no acknowledgement lands here. It is a configuration answer, and
            // the operator needs the reason rather than a red cross.
            return new OllamaCheck(
                    false, false, model, aiReview.baseUrl(), List.of(), refused.getMessage(),
                    provider.wireName(), remoteAllowed);
        }

        // **Checked before the call, not after it fails.** OpenAI answers an unauthenticated
        // request with a 401 that `availableModels` swallows into "unreachable" — sending the
        // operator to check a network path that is fine, over a key they never set.
        if (provider == AiProvider.OPENAI && !aiReview.hasOpenAiKey()) {
            return new OllamaCheck(false, false, model, url, List.of(),
                    "No API key is stored for " + url + ". Set one, or point this at a local endpoint that "
                            + "authenticates nobody.",
                    provider.wireName(), remoteAllowed);
        }

        List<String> models = aiReview.availableModels();
        // `availableModels` never throws and falls back to suggestions, which is right for a
        // dropdown and wrong for a test: the fallback list is indistinguishable from an installed
        // one unless the URL is asked a second time. Equality with the suggestions is what
        // separates "the host answered" from "the host did not".
        boolean reachable = !models.equals(AiReview.FALLBACK_MODEL_SUGGESTIONS)
                && !models.equals(AiReview.OPENAI_MODEL_SUGGESTIONS);

        if (!reachable) {
            return new OllamaCheck(false, false, model, url, List.of(),
                    "No answer from " + url + ". Is " + name + " running, and reachable from this process?",
                    provider.wireName(), remoteAllowed);
        }
        boolean installed = models.contains(model);
        return new OllamaCheck(
                true,
                installed,
                model,
                url,
                models,
                installed
                        ? "Reachable, and \"" + model + "\" is available."
                        : "Reachable, but \"" + model + "\" is not available there. Pick one of the "
                                + models.size() + " it offers.",
                provider.wireName(),
                remoteAllowed);
    }

    /**
     * Stores the API key for an OpenAI-compatible endpoint.
     *
     * <p>Its own route for the same reasons as the tracker token and the webhook secret: encrypted
     * at rest, never rendered back into a form, and an exception at every step of the generic path
     * is an exception somebody eventually forgets.
     */
    @RequiresAdministrator
    @PutMapping("/ai-openai-key")
    public Map<String, Boolean> setOpenAiKey(
            @RequestBody SecretRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        String key = body == null || body.secret() == null ? "" : body.secret();
        aiReview.setOpenAiKey(key);

        audit.record(new AuditLogService.Record(
                AuditOperation.SETTING_UPDATED,
                Setting.AI_REVIEW_OPENAI_KEY.key(),
                // Never the value: whoever reads this table would otherwise be able to spend the
                // account, and the audit log is deliberately never purged.
                key.isBlank()
                        ? "AI provider API key cleared."
                        : "AI provider API key stored.",
                principal.user().map(user -> user.getUsername()).orElse(null),
                request.getRemoteAddr(),
                request.getHeader("User-Agent")));

        return Map.of("configured", !key.isBlank());
    }

    /** Whether a key is stored. Never the key — see the route above. */
    @GetMapping("/ai-openai-key")
    public Map<String, Boolean> openAiKeyState() {
        return Map.of("configured", aiReview.hasOpenAiKey());
    }

    /**
     * Stores the secret the tracker presents when it calls us.
     *
     * <p>It had no route of its own and was read straight out of the settings table, which is how
     * it came to be the one credential stored in the clear <em>by design</em>. It authenticates the
     * only anonymous mutating route in the system: a holder can close somebody's finding.
     */
    @RequiresAdministrator
    @PutMapping("/ticket-webhook-secret")
    public Map<String, Boolean> setTicketWebhookSecret(
            @RequestBody SecretRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        String secret = body == null || body.secret() == null ? "" : body.secret();
        tickets.setWebhookSecret(secret);

        audit.record(new AuditLogService.Record(
                AuditOperation.SETTING_UPDATED,
                Setting.TICKET_WEBHOOK_SECRET.key(),
                // Never the value: it would let whoever reads this table forge a triage decision,
                // and the audit log is deliberately never purged.
                secret.isBlank()
                        ? "Inbound webhook secret cleared — the webhook route accepts anonymous callers again."
                        : "Inbound webhook secret stored — the webhook route authenticates its caller.",
                principal.user().map(user -> user.getUsername()).orElse(null),
                request.getRemoteAddr(),
                request.getHeader("User-Agent")));

        return Map.of("configured", !secret.isBlank());
    }

    /** Whether one is configured. Never the secret — see the route above. */
    @GetMapping("/ticket-webhook-secret")
    public Map<String, Boolean> ticketWebhookSecretState() {
        return Map.of("configured", tickets.hasWebhookSecret());
    }
}
