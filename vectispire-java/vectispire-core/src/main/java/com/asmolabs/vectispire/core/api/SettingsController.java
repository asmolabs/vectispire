package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.asmolabs.vectispire.core.services.ai.AiReviewService;
import com.asmolabs.vectispire.core.services.notifications.NotificationService;
import com.asmolabs.vectispire.core.services.platform.SettingsAdministrationService;
import com.asmolabs.vectispire.core.services.tickets.TicketService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.RequiresAdministrator;
import com.asmolabs.vectispire.core.api.security.RequiresSecurityLead;
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
 * <p><b>Every write is audited</b> — by {@link SettingsAdministrationService}, which performs it.
 */
@RestController
@RequestMapping("/api/v1/settings")
// The catalog is readable by any account — the screen needs the labels and the types — and the
// two writing routes narrow it to administrators. A method's own marker wins over the class's,
// which is what lets one controller carry two different rules without a second controller.
@RequiresAccount
public class SettingsController {

    private final SettingsAdministrationService administration;
    private final TicketService tickets;
    private final AiReviewService aiReview;
    private final NotificationService notifications;

    /** The three services below are read for their "configured" state only; every write goes through {@code administration}. */
    public SettingsController(
            SettingsAdministrationService administration,
            TicketService tickets,
            AiReviewService aiReview,
            NotificationService notifications) {
        this.administration = administration;
        this.tickets = tickets;
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
            boolean configured,

            // **True when this setting decides a rule rather than a parameter**, and only the
            // platform governor may write it.
            //
            // Carried by the response, and not copied into the screen: the rule here is a set of
            // sections, and copying it into the front end would have made a second source, compared
            // with the first only by the surprise of a 403. The screen shows these settings to
            // whoever may read them and offers the edit only to whoever may make it.
            @JsonProperty("governor_only") boolean governorOnly,
            @JsonProperty("administrator_only") boolean administratorOnly) {}

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
        return new Catalog(administration.catalog(principal.user()).stream()
                .map(entry -> {
                    Setting setting = entry.setting();
                    return new SettingView(
                            setting.key(),
                            setting.type().name().toLowerCase(java.util.Locale.ROOT),
                            // The label, not the enum constant. `Section` carries one and nothing
                            // called it, so every card on this screen was titled `model_review` and
                            // `end_of_life` — the raw name, lowercased, straight from the wire.
                            setting.section().label(),
                            setting.label(),
                            setting.help(),
                            setting.defaultValue(),
                            entry.value(),
                            entry.configured(),
                            entry.governorOnly(),
                            entry.administratorOnly());
                })
                .toList());
    }

    @RequiresSecurityLead
    @PutMapping
    public Map<String, Integer> update(
            @RequestBody Map<String, String> body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        SettingsAdministrationService.Applied applied =
                administration.update(body, principal.user(), RequestActors.of(principal, request));
        return Map.of("updated", applied.count());
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
        administration.setTicketToken(token, RequestActors.of(principal, request));
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
        administration.setWebhookSigningSecret(secret, RequestActors.of(principal, request));
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
     * <p><b>Narrowed to whoever may configure the endpoint</b> — the same marker as the route that
     * writes it, rather than the narrower administrator one: testing a field one is allowed to
     * edit should not need a second account. Under the class marker alone it was
     * reachable by any signed-in reader, and it answers with the configured URL: the one value
     * `ai_review_ollama_url` is marked {@code SECRET} to keep out of exactly those hands, since an
     * internal model endpoint describes the estate's topology. It also makes the server open an
     * outbound connection on the caller's say-so, which is not a reader's to spend.
     */
    @RequiresSecurityLead
    @PostMapping("/ollama-test")
    public OllamaCheck testOllama() {
        SettingsAdministrationService.EndpointCheck check = administration.checkAiEndpoint();
        return new OllamaCheck(
                check.reachable(),
                check.modelInstalled(),
                check.model(),
                check.url(),
                check.models(),
                check.detail(),
                check.provider(),
                check.remoteAllowed());
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
        administration.setOpenAiKey(key, RequestActors.of(principal, request));
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
        administration.setTicketWebhookSecret(secret, RequestActors.of(principal, request));
        return Map.of("configured", !secret.isBlank());
    }

    /** Whether one is configured. Never the secret — see the route above. */
    @GetMapping("/ticket-webhook-secret")
    public Map<String, Boolean> ticketWebhookSecretState() {
        return Map.of("configured", tickets.hasWebhookSecret());
    }


}
