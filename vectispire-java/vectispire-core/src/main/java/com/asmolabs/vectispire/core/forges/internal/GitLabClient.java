package com.asmolabs.vectispire.core.forges.internal;

import com.asmolabs.vectispire.common.domain.forges.ForgeConnectionRefusal;
import com.asmolabs.vectispire.common.domain.forges.ForgeConnectionRefusal.Reason;
import com.asmolabs.vectispire.common.domain.forges.ForgeCredential;
import com.asmolabs.vectispire.common.domain.forges.ForgeKind;
import com.asmolabs.vectispire.common.domain.forges.ForgeVersion;
import com.asmolabs.vectispire.core.outbound.OutboundJson;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * GitLab's REST API v4 — gitlab.com, self-managed and Dedicated alike (decision 0037 §1).
 *
 * <p><b>The probe is three requests</b>: the token's own description ({@code GET
 * /personal_access_tokens/self}: its scopes, its expiry, whether it is active — personal, group and
 * project access tokens alike, since the last two are personal tokens of a bot user), the server's
 * version ({@code GET /version}, refused under 16), and the user the token acts as ({@code GET /user}:
 * {@code bot} tells a group or project access token from a person's). The scopes are judged right after
 * the first answer, so a token broader than {@code read_api} is refused before it is presented again.
 *
 * <p>{@code PRIVATE-TOKEN} rather than {@code Authorization: Bearer}: GitLab accepts both for these
 * tokens, and the first is the one its documentation and its administrators recognise in a request log.
 */
@Component
class GitLabClient implements ForgeClient {

    private final OutboundJson outbound;

    GitLabClient(OutboundJson outbound) {
        this.outbound = outbound;
    }

    @Override
    public ForgeKind kind() {
        return ForgeKind.GITLAB;
    }

    @Override
    public Probe probe(Target target, String token) {
        String api = target.address().apiRoot();
        Map<String, String> headers = Map.of("PRIVATE-TOKEN", token);

        JsonNode self = expect(get(target, api + "/personal_access_tokens/self", headers), "the token's description",
                target);
        if (!self.path("active").asBoolean(true) || self.path("revoked").asBoolean(false)) {
            throw new ForgeConnectionRefusal(Reason.TOKEN_REJECTED,
                    "GitLab reports this token as revoked or inactive.");
        }
        List<String> scopes = new ArrayList<>();
        self.path("scopes").forEach(scope -> scopes.add(scope.asText()));
        // Judged now, before the token is presented again; the bot flag comes with the third answer.
        ForgeCredential.gitlab(scopes, false);
        Optional<Instant> expiresAt = expiryOf(self.path("expires_at"));

        JsonNode versionAnswer = expect(get(target, api + "/version", headers), "its version", target);
        Optional<String> version = Optional.ofNullable(versionAnswer.path("version").textValue())
                .filter(value -> !value.isBlank());
        if (version.flatMap(found -> ForgeVersion.tooOld(target.address().edition(), found)).orElse(false)) {
            throw new ForgeConnectionRefusal(Reason.VERSION_UNSUPPORTED, "This GitLab is version " + version.get()
                    + "; GitLab " + ForgeVersion.GITLAB_MINIMUM_MAJOR + " or later is required.");
        }

        JsonNode user = expect(get(target, api + "/user", headers), "the token's user", target);
        boolean bot = user.path("bot").asBoolean(false);
        return new Probe(ForgeCredential.gitlab(scopes, bot), expiresAt, version);
    }

    private OutboundJson.Answer get(Target target, String url, Map<String, String> headers) {
        return outbound.answer(url, target.policy(), "GitLab at " + target.address().baseUrl(), headers, target.trust());
    }

    private static JsonNode expect(OutboundJson.Answer answer, String what, Target target) {
        return switch (answer.status()) {
            case 200 -> answer.body().orElseThrow(() -> new ForgeConnectionRefusal(Reason.UNREACHABLE,
                    "GitLab answered " + what + " with no document."));
            case 401 -> throw new ForgeConnectionRefusal(Reason.TOKEN_REJECTED,
                    "GitLab rejected this token (HTTP 401): it is wrong, expired or revoked.");
            case 403 -> throw new ForgeConnectionRefusal(Reason.SCOPE_MISSING,
                    "GitLab refused to answer " + what + " with this token (HTTP 403): it needs the read_api scope.");
            // A server older than the token self-description (15.5) answers 404 to it.
            case 404 -> throw new ForgeConnectionRefusal(Reason.VERSION_UNSUPPORTED, "GitLab at "
                    + target.address().baseUrl() + " does not answer " + what + " (HTTP 404): it is not GitLab "
                    + ForgeVersion.GITLAB_MINIMUM_MAJOR + " or later, or the address is not GitLab's web address.");
            default -> throw new ForgeConnectionRefusal(Reason.UNREACHABLE,
                    "GitLab answered " + what + " with HTTP " + answer.status() + ".");
        };
    }

    /** {@code expires_at} is a date, the token's last valid day being the one before it at midnight UTC. */
    private static Optional<Instant> expiryOf(JsonNode value) {
        if (!value.isTextual()) {
            return Optional.empty();
        }
        try {
            return Optional.of(LocalDate.parse(value.asText()).atStartOfDay(ZoneOffset.UTC).toInstant());
        } catch (DateTimeParseException unreadable) {
            return Optional.empty();
        }
    }
}
