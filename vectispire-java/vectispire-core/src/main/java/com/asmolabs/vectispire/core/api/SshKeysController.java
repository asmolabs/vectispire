package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.core.access.web.security.RequestActors;
import com.asmolabs.vectispire.core.access.web.security.RequiresAdministrator;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.services.targets.SshKeyAdministrationService;
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

/** The deployment keys. Administrators only, and the private half never leaves. */
@RestController
@RequestMapping("/api/v1/ssh-keys")
@RequiresAdministrator
public class SshKeysController {

    private final SshKeyAdministrationService administration;

    public SshKeysController(SshKeyAdministrationService administration) {
        this.administration = administration;
    }

    /**
     * @param encryptionState deserves a column and not a log line: a key readable only under a
     *     previous encryption key has not finished being rotated, and one that <em>no</em>
     *     configured key reads will fail the next clone that needs it — at scan time, in a
     *     worker thread, hours later
     */
    public record SshKeySummary(
            UUID id,
            String name,
            String publicKey,
            Instant createdAt,
            String encryptionState,
            long usedByRepositories) {}

    /** The names the Angular client sends. See {@code ClientContractTest} for why they differ. */
    public record SshKeyCreateRequest(
            String name,
            @JsonProperty("private_key") String privateKey,
            @JsonProperty("public_key") String publicKey) {}

    @GetMapping
    public List<SshKeySummary> list() {
        return administration.list().stream().map(SshKeysController::summaryOf).toList();
    }

    @PostMapping
    public SshKeySummary create(
            @RequestBody SshKeyCreateRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        return summaryOf(administration.add(body.name(), body.privateKey(), body.publicKey(), RequestActors.of(principal, request)));
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void remove(
            @PathVariable UUID id,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        administration.remove(id, RequestActors.of(principal, request));
    }

    private static SshKeySummary summaryOf(SshKeyAdministrationService.KeyView key) {
        return new SshKeySummary(
                key.id(), key.name(), key.publicKey(), key.createdAt(), key.encryptionState(), key.usedByRepositories());
    }
}
