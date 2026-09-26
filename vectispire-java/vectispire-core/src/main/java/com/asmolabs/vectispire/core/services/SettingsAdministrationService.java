package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.aireview.AiProvider;
import com.asmolabs.vectispire.common.domain.aireview.AiReview;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.siem.SecurityEventType;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.persistence.UserEntity;
import com.asmolabs.vectispire.core.repositories.Users;
import com.asmolabs.vectispire.core.services.ai.AiReviewService;
import com.asmolabs.vectispire.core.services.audit.AuditLogService;
import com.asmolabs.vectispire.core.services.audit.RequestActor;
import com.asmolabs.vectispire.core.services.shared.SettingsService;
import com.asmolabs.vectispire.core.services.tickets.TicketService;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;

/**
 * The rules behind the settings screen: what a reader may see of the catalog, what a save may
 * change, and whether the configured AI endpoint answers.
 *
 * <p><b>The catalog decides everything.</b> A key that is not in it is refused on write, so the
 * settings table cannot fill with keys no service reads — the exact state that makes an operator
 * believe they configured something.
 *
 * <p><b>Every write is audited</b>, like any administration action: moving the notification
 * threshold from high to critical changes what the organization sees, and that is the kind of
 * decision one wants to be able to date. The four credentials are audited too, and never with
 * their value.
 */
@Service
public class SettingsAdministrationService {

    /** The sections whose contents are a rule, not a setting. */
    private static final Set<Setting.Section> GOVERNANCE_SECTIONS =
            Set.of(Setting.Section.ACCESS, Setting.Section.TRIAGE);

    /**
     * The longest credential one of the four secret routes accepts.
     *
     * <p>Encrypted, a secret grows by a third plus about forty characters, and in UTF-8 a character
     * may take three bytes: 8,192 characters stays inside MySQL's 65,535-byte {@code text}, which
     * the column has been since V38. Real ones are two orders of magnitude shorter — an Atlassian
     * token is 192 characters, an OpenAI project key a little more — so anything near this is a
     * paste of the wrong thing, and it is better said at the form than as a 500.
     */
    static final int MAX_SECRET_LENGTH = 8_192;

    private static final List<String> APPROVER_ROLES = Arrays.stream(Role.values())
            .filter(Role::canApproveTriage)
            .map(Enum::name)
            .toList();

    private final SettingsService settings;
    private final AiReviewService aiReview;
    /** Read for one question only: is anybody left to approve? */
    private final Users users;
    private final TicketService tickets;
    private final NotificationService notifications;
    private final AuditLogService audit;

    public SettingsAdministrationService(
            SettingsService settings,
            AiReviewService aiReview,
            Users users,
            TicketService tickets,
            NotificationService notifications,
            AuditLogService audit) {
        this.settings = settings;
        this.aiReview = aiReview;
        this.users = users;
        this.tickets = tickets;
        this.notifications = notifications;
        this.audit = audit;
    }

    /**
     * One catalog entry as this reader may see it.
     *
     * @param value the effective value, default included, or {@code null} when it may not leave
     * @param governorOnly true when this setting decides a rule rather than a parameter, and only
     *     the platform governor may write it
     * @param administratorOnly true when it decides where a credential is sent, and only the role
     *     that may set that credential may change it — see {@link Setting#directsCredential()}
     */
    public record Entry(
            Setting setting, String value, boolean configured, boolean governorOnly, boolean administratorOnly) {}

    /**
     * What a save changed, in the words its audit entry uses.
     *
     * @param keys the changed keys, comma-separated — the audit entry's resource
     * @param description each change as {@code key = value}, never a credential: those are refused
     *     before they get here
     */
    public record Applied(int count, String keys, String description) {}

    /** The configured AI endpoint's answer to "are you there, and do you hold the model?". */
    public record EndpointCheck(
            boolean reachable,
            boolean modelInstalled,
            String model,
            String url,
            List<String> models,
            String detail,
            String provider,
            boolean remoteAllowed) {}

    public List<Entry> catalog(Optional<UserEntity> reader) {
        Map<String, String> stored = settings.stored();
        // **A sensitive setting's value only leaves for an administrator.** A webhook URL is a
        // bearer capability: whoever reads it can post in the channel where the team awaits
        // Vectispire's alerts. The catalog itself stays readable by everybody — the screen needs
        // the labels and the types.
        boolean isAdmin = reader
                .flatMap(user -> Role.of(user.getRole()))
                .map(Role::isAdministrative)
                .orElse(false);

        List<Entry> entries = new ArrayList<>();
        for (Setting setting : Setting.values()) {
            entries.add(new Entry(
                    setting,
                    // **A credential's value leaves for nobody, an administrator included.** What
                    // is stored is a ciphertext; returning it puts the encrypted blob in a browser
                    // tab and a proxy log, and it is of no use to a form that cannot re-submit it
                    // anyway. The screens ask "is one configured" through the route that owns it.
                    setting.isEncrypted() || (setting.isSecret() && !isAdmin)
                            ? null
                            : stored.getOrDefault(setting.key(), setting.defaultValue()),
                    stored.containsKey(setting.key()),
                    GOVERNANCE_SECTIONS.contains(setting.section()),
                    setting.directsCredential().isPresent()));
        }
        return entries;
    }

    /**
     * Validates every change, then writes them all.
     *
     * <p>All validated before any is written: a partial write would leave the configuration
     * half-way between two intended states.
     */
    public Applied update(Map<String, String> body, Optional<UserEntity> writer, RequestActor actor) {
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
            // **The two settings that decide rules, reserved to the governor.** They are
            // `target_visibility` — who sees which targets — and `triage_four_eyes_required` — does
            // dismissing a vulnerability take two people. Four-eyes was bypassable by anyone who
            // could both switch it off and triage: switch off, settle alone, switch back on, one
            // audit entry for a trace. What closes the hole is not removing the right to approve —
            // the service settles everyone's decision when the setting is off — but breaking the
            // conjunction. The one role that can lift the rule is the one that cannot act under
            // it.
            if (GOVERNANCE_SECTIONS.contains(setting.section()) && !governsPlatform(writer)) {
                throw new AccessDeniedException(
                        setting.label() + " decides a rule rather than a setting: only a platform "
                                + "governor may change it, because it is the one role that cannot "
                                + "act under it.");
            }
            // **A credential's destination moves only in the hands of whoever may set the credential.**
            // Only on a change: a screen that saves every field it shows sends these back unchanged,
            // and refusing that would lock a CISO out of the rest of the section.
            if (setting.directsCredential().isPresent()
                    && !value.equals(settings.get(setting))
                    && !administrative(writer)) {
                Setting credential = setting.directsCredential().get();
                throw new AccessDeniedException(
                        setting.label() + " decides where " + credential.label().toLowerCase(java.util.Locale.ROOT)
                                + " is sent, and only an administrator — who alone may set that credential — "
                                + "may change it.");
            }
            // **Switching on a two-person control requires that there be two.** Without this
            // guard, switching it on where no approver is active puts every decision in a queue
            // nobody can empty — a control that blocks instead of controlling, and whose failure
            // shows only at the first triage.
            if (setting == Setting.FOUR_EYES_APPROVAL_REQUIRED && isTruthy(value) && noApproverExists()) {
                throw new IllegalArgumentException(
                        "No active account can approve a triage: switching four-eyes on would put "
                                + "every decision in a queue nobody can empty. Create an "
                                + "administrator, a CISO or a security lead first.");
            }
            // **A credential has one door, and this is not it.** Each of these has a route that
            // encrypts the value before it reaches the database; this path stores what it is
            // handed. Left open, it wrote tracker tokens, webhook secrets and provider keys in the
            // clear — 200 OK, no warning — and the audit description would then have carried the
            // value itself into a log that is deliberately never purged.
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
        Map<Setting, String> pending = new EnumMap<>(Setting.class);
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

        changes.forEach(change -> settings.set(change.setting(), change.value()));

        // **The acceptance is stamped here, by the server, or erased here.** Recorded after the
        // write so it describes a configuration that exists, and only on the transition — saving
        // an unrelated setting while the switch is already on must not rewrite whose decision it
        // was, or the record would name whoever edited the screen last.
        if (pending.containsKey(Setting.AI_REVIEW_ALLOW_REMOTE)
                && !pending.get(Setting.AI_REVIEW_ALLOW_REMOTE).equals(previousAcknowledgement)) {
            if (remoteAfter) {
                aiReview.recordRiskAcknowledgement(
                        writer.map(user -> user.getUsername()).orElse(""), Instant.now());
            } else {
                aiReview.clearRiskAcknowledgement();
            }
        }

        Applied applied = new Applied(
                changes.size(),
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
                        .orElse(""));

        AuditLogService.Record entry = actor.entry(AuditOperation.SETTING_UPDATED, applied.keys(), applied.description());
        // Forwarded when one of the settings saved decides what the deployment protects — see
        // Setting#governsSecurity. The SLA windows and the retention periods stay out of a SOC's feed.
        audit.record(changes.stream().anyMatch(change -> change.setting().governsSecurity())
                ? entry.signalling(SecurityEventType.SECURITY_SETTING_CHANGED)
                : entry);
        return applied;
    }

    /**
     * Stores the tracker token, or clears it when blank.
     *
     * <p>The value is <b>not</b> logged, unlike the other settings: the audit trail is readable by
     * every administrator.
     */
    public void setTicketToken(String token, RequestActor actor) {
        refuseOversized(token, "The tracker token");
        tickets.setToken(token);
        audit.record(actor.entry(
                AuditOperation.SETTING_UPDATED,
                Setting.TICKET_TOKEN.key(),
                token.isBlank() ? "Tracker token cleared." : "Tracker token stored.")
                .signalling(SecurityEventType.SECURITY_SETTING_CHANGED));
    }

    /**
     * Stores the webhook signing secret, or clears it when blank.
     *
     * <p>Never the value in the entry. Whoever reads the audit table could otherwise forge a
     * message into every channel this deployment announces to — and the audit log is deliberately
     * never purged, so it would outlive the secret's own rotation.
     */
    public void setWebhookSigningSecret(String secret, RequestActor actor) {
        refuseOversized(secret, "The webhook signing secret");
        notifications.setSigningSecret(secret);
        audit.record(actor.entry(
                AuditOperation.SETTING_UPDATED,
                Setting.WEBHOOK_SIGNING_SECRET.key(),
                secret.isBlank()
                        ? "Webhook signing secret cleared — messages are sent unsigned."
                        : "Webhook signing secret stored — messages are signed.")
                .signalling(SecurityEventType.SECURITY_SETTING_CHANGED));
    }

    /**
     * Stores the OpenAI-compatible provider's key, or clears it when blank.
     *
     * <p>Never the value in the entry: whoever reads the audit table would otherwise be able to
     * spend the account, and the audit log is deliberately never purged.
     */
    public void setOpenAiKey(String key, RequestActor actor) {
        refuseOversized(key, "The API key");
        aiReview.setOpenAiKey(key);
        audit.record(actor.entry(
                AuditOperation.SETTING_UPDATED,
                Setting.AI_REVIEW_OPENAI_KEY.key(),
                key.isBlank() ? "AI provider API key cleared." : "AI provider API key stored.")
                .signalling(SecurityEventType.SECURITY_SETTING_CHANGED));
    }

    /**
     * Stores the secret the tracker presents when it calls us, or clears it when blank.
     *
     * <p>Never the value in the entry: it would let whoever reads the audit table forge a triage
     * decision, and the audit log is deliberately never purged.
     */
    public void setTicketWebhookSecret(String secret, RequestActor actor) {
        refuseOversized(secret, "The inbound webhook secret");
        tickets.setWebhookSecret(secret);
        audit.record(actor.entry(
                AuditOperation.SETTING_UPDATED,
                Setting.TICKET_WEBHOOK_SECRET.key(),
                secret.isBlank()
                        ? "Inbound webhook secret cleared — the webhook route accepts anonymous callers again."
                        : "Inbound webhook secret stored — the webhook route authenticates its caller.")
                .signalling(SecurityEventType.SECURITY_SETTING_CHANGED));
    }

    /**
     * Asks the configured endpoint what it holds.
     *
     * <p>It reports rather than throws: "unreachable" is an answer to the question the test button
     * asks, not an error in asking it. The check runs the same URL validation as a real call, so
     * a refusal here is the refusal a report would get.
     */
    public EndpointCheck checkAiEndpoint() {
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
            return new EndpointCheck(
                    false, false, model, aiReview.baseUrl(), List.of(), refused.getMessage(),
                    provider.wireName(), remoteAllowed);
        }

        // **Checked before the call, not after it fails.** OpenAI answers an unauthenticated
        // request with a 401 that `availableModels` swallows into "unreachable" — sending the
        // operator to check a network path that is fine, over a key they never set.
        if (provider == AiProvider.OPENAI && !aiReview.hasOpenAiKey()) {
            return new EndpointCheck(false, false, model, url, List.of(),
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
            return new EndpointCheck(false, false, model, url, List.of(),
                    "No answer from " + url + ". Is " + name + " running, and reachable from this process?",
                    provider.wireName(), remoteAllowed);
        }
        boolean installed = models.contains(model);
        return new EndpointCheck(
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

    /** Checked on the trimmed value, which is what each route stores. */
    private static void refuseOversized(String secret, String what) {
        BoundedText.within(secret == null ? "" : secret.trim(), MAX_SECRET_LENGTH, what);
    }

    /** The role that decides the rules, and the only one that cannot act under them. */
    private static boolean administrative(Optional<UserEntity> writer) {
        return writer.flatMap(u -> Role.of(u.getRole())).map(Role::isAdministrative).orElse(false);
    }

    private static boolean governsPlatform(Optional<UserEntity> writer) {
        return writer.flatMap(u -> Role.of(u.getRole())).map(Role::governsPlatform).orElse(false);
    }

    /**
     * Is anyone left to approve?
     *
     * <p>Counted in the database rather than deduced from a role: the question is about
     * <em>active</em> accounts, and an estate may perfectly well declare a role nobody holds.
     */
    private boolean noApproverExists() {
        return users.countActiveAdministratorsExcluding(APPROVER_ROLES, -1L) == 0;
    }

    private static boolean isTruthy(String value) {
        return "true".equalsIgnoreCase(value) || "1".equals(value);
    }
}
