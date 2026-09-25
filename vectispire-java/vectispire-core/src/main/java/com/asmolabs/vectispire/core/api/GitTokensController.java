package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.core.api.security.RequiresAdministrator;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.services.GitTokenAdministrationService;
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

/** HTTPS clone tokens. Administrators only, and the token never leaves (decision 0022). */
@RestController
@RequestMapping("/api/v1/git-tokens")
@RequiresAdministrator
public class GitTokensController {

    private final GitTokenAdministrationService administration;

    public GitTokensController(GitTokenAdministrationService administration) {
        this.administration = administration;
    }

    /** Never the token: what a screen needs to choose one and to see whether it still decrypts. */
    public record GitTokenSummary(
            UUID id,
            String name,
            String host,
            String username,
            Instant createdAt,
            String encryptionState,
            long usedByRepositories) {}

    public record GitTokenCreateRequest(String name, String host, String username, String token) {}

    @GetMapping
    public List<GitTokenSummary> list() {
        return administration.list().stream().map(GitTokensController::summaryOf).toList();
    }

    @PostMapping
    public GitTokenSummary create(
            @RequestBody GitTokenCreateRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return summaryOf(administration.add(
                body == null ? null : body.name(),
                body == null ? null : body.host(),
                body == null ? null : body.username(),
                body == null ? null : body.token(),
                RequestActors.of(principal, request)));
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void remove(
            @PathVariable UUID id,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        administration.remove(id, RequestActors.of(principal, request));
    }

    private static GitTokenSummary summaryOf(GitTokenAdministrationService.TokenView token) {
        return new GitTokenSummary(
                token.id(), token.name(), token.host(), token.username(), token.createdAt(),
                token.encryptionState(), token.usedByRepositories());
    }
}
