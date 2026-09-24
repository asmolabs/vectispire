package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.core.api.security.RequiresAdministrator;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.services.ApiKeyAdministrationService;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/** The API keys. Administrators only. */
@RestController
@RequestMapping("/api/v1/api-keys")
@RequiresAdministrator
public class ApiKeysController {

    private final ApiKeyAdministrationService administration;

    public ApiKeysController(ApiKeyAdministrationService administration) {
        this.administration = administration;
    }

    /**
     * What a key shows.
     *
     * <p>{@code keyHash} is not on it; {@code prefix} is, and it is not a secret.
     *
     * @param isExpired computed by the server and not on the screen: an expired key is refused by
     *     the server, and two notions of "expired" would eventually disagree by a timezone
     */
    public record ApiKeySummary(
            UUID id,
            String name,
            String prefix,
            List<String> scopes,
            String targetKind,
            Long targetId,
            String targetLabel,
            Instant createdAt,
            Instant lastUsedAt,
            Instant expiresAt,
            boolean isExpired) {}

    public record ApiKeyCreateRequest(
            String name,
            List<String> scopes,
            @JsonProperty("target_kind") String targetKind,
            @JsonProperty("target_id") Long targetId,
            @JsonProperty("expires_in_days") Integer expiresInDays) {}

    /** @param secret the only occurrence of the plaintext. It will never appear again */
    public record IssuedKey(ApiKeySummary key, String secret) {}

    public record TargetOption(Long id, String label) {}

    public record Targets(List<TargetOption> repositories, List<TargetOption> containers) {}

    @GetMapping
    public List<ApiKeySummary> list() {
        return administration.list().stream().map(ApiKeysController::summaryOf).toList();
    }

    /** Issues a key and returns it once — see {@link ApiKeyAdministrationService#issue}. */
    @PostMapping
    public IssuedKey create(
            @RequestBody ApiKeyCreateRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        ApiKeyAdministrationService.Issued issued = administration.issue(
                new ApiKeyAdministrationService.Request(
                        body.name(), body.scopes(), body.targetKind(), body.targetId(), body.expiresInDays()),
                actor(principal, request));
        return new IssuedKey(summaryOf(issued.key()), issued.secret());
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void remove(
            @PathVariable UUID id,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        administration.revoke(id, actor(principal, request));
    }

    /** The targets a key can be restricted to, so the screen offers names rather than numbers. */
    @GetMapping("/targets")
    public Targets targets() {
        ApiKeyAdministrationService.TargetOptions options = administration.targets();
        return new Targets(
                options.repositories().stream().map(o -> new TargetOption(o.id(), o.label())).toList(),
                options.containers().stream().map(o -> new TargetOption(o.id(), o.label())).toList());
    }

    private static ApiKeySummary summaryOf(ApiKeyAdministrationService.KeyView key) {
        return new ApiKeySummary(
                key.id(),
                key.name(),
                key.prefix(),
                key.scopes(),
                key.targetKind(),
                key.targetId(),
                key.targetLabel(),
                key.createdAt(),
                key.lastUsedAt(),
                key.expiresAt(),
                key.expired());
    }

    private static ApiKeyAdministrationService.Actor actor(VectispirePrincipal principal, HttpServletRequest request) {
        return new ApiKeyAdministrationService.Actor(
                principal == null ? null : principal.user().map(user -> user.getUsername()).orElse(null),
                request.getRemoteAddr(),
                request.getHeader("User-Agent"));
    }
}
