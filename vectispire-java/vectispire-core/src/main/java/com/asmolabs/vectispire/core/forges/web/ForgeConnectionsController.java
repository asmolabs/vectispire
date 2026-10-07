package com.asmolabs.vectispire.core.forges.web;

import com.asmolabs.vectispire.core.access.web.security.RequestActors;
import com.asmolabs.vectispire.core.access.web.security.RequiresAdministrator;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.forges.ForgeConnectionService;
import com.asmolabs.vectispire.core.forges.ForgeConnectionView;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * Forge connections (decision 0037 §2). Administrators only, as for SSH keys, HTTPS tokens and
 * repositories: a connection reveals the name of every repository an organisation holds. Integration keys
 * are not accepted in v1. The service probes, decides and audits; this maps the requests, and the token
 * never comes back out.
 */
@Tag(name = "Forge connections", description = "Read-only credentials to GitHub and GitLab, for discovering repositories")
@RestController
@RequestMapping("/api/v1/forge-connections")
@RequiresAdministrator
public class ForgeConnectionsController {

    private final ForgeConnectionService connections;

    public ForgeConnectionsController(ForgeConnectionService connections) {
        this.connections = connections;
    }

    /**
     * @param kind {@code github} or {@code gitlab}
     * @param baseUrl the web address, https only; blank for github.com or gitlab.com
     * @param owner GitHub's organisation or user the token was issued for; none for GitLab
     * @param internalNetwork the server is on the internal network; refused for github.com, gitlab.com and ghe.com
     * @param caPem the CA the server's certificate chains to, in PEM, in place of the runtime's trust store
     */
    public record ForgeConnectionRequest(
            String name, String kind, String baseUrl, String owner, Boolean internalNetwork, String caPem, String token) {}

    /** @param caPem blank unpins the CA; absent keeps it */
    public record ForgeConnectionChange(String name, Boolean internalNetwork, String caPem) {}

    public record ForgeTokenReplacement(String token) {}

    @Operation(summary = "List forge connections", description = "Never the token: the forge, the address, the "
            + "owner, the credential the forge identified with its scopes (null when not reported — a GitHub "
            + "fine-grained token), whether it can write (null when not reported), its expiry, the server's "
            + "version, and encryptionState — previous_key while an ENCRYPTION_KEY rotation has not reached it; state, "
            + "suspended while the platform governor has disabled the forge's integration (decision 0040), and the "
            + "integration's key.")
    @GetMapping
    public List<ForgeConnectionView> listForgeConnections() {
        return connections.list();
    }

    @Operation(summary = "Read forge connection", description = "404 when no connection has that id.")
    @GetMapping("/{id}")
    public ForgeConnectionView getForgeConnection(@PathVariable UUID id) {
        return connections.get(id);
    }

    @Operation(summary = "Create forge connection", description = "The token is probed against the forge before "
            + "anything is kept, through the outbound guard — public addresses only unless internalNetwork, "
            + "link-local and Vectispire's own endpoints never — and refused (400) when the forge rejects it, "
            + "reports a scope outside the read-only allow-list (GitLab: read_api, read_repository, read_registry, "
            + "read_user; GitHub: a fine-grained token, or on Enterprise Server a classic one with repo, public_repo, "
            + "read:org, read:user, user:email, flagged canWrite), a server older than GitLab 16 or GHES 3.12, or "
            + "an owner it does not know. Audited FORGE_CONNECTION_CHANGED and signalled VECTI-SEC-034; a blocked "
            + "address or a refused scope is audited FORGE_CONNECTION_REFUSED and signalled VECTI-SEC-036. 409 "
            + "integration-disabled, nothing probed, when the platform governor has disabled that forge.")
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public ForgeConnectionView createForgeConnection(
            @RequestBody(required = false) ForgeConnectionRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return connections.create(
                body == null ? null : new ForgeConnectionService.Creation(body.name(), body.kind(), body.baseUrl(),
                        body.owner(), body.internalNetwork(), body.caPem(), body.token()),
                RequestActors.of(principal, request));
    }

    @Operation(summary = "Replace forge connection token", description = "Rotation in place: the new token is "
            + "probed as at creation, and the connection keeps its id and everything that hangs on it. 400 as at "
            + "creation, 409 integration-disabled for a suspended connection; VECTI-SEC-034, or VECTI-SEC-036 for a "
            + "refused scope.")
    @PutMapping("/{id}/token")
    public ForgeConnectionView replaceForgeConnectionToken(
            @PathVariable UUID id,
            @RequestBody(required = false) ForgeTokenReplacement body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return connections.replaceToken(id, body == null ? null : body.token(), RequestActors.of(principal, request));
    }

    @Operation(summary = "Update forge connection", description = "Rename it, or change how its token is presented "
            + "— the internal-network statement, the pinned CA (blank unpins it) — which probes the stored token "
            + "again first and signals VECTI-SEC-034 — 409 integration-disabled for a suspended connection, which "
            + "may still be renamed. The address cannot change: another server is another connection. Saving "
            + "re-seals the token under the current ENCRYPTION_KEY.")
    @PatchMapping("/{id}")
    public ForgeConnectionView updateForgeConnection(
            @PathVariable UUID id,
            @RequestBody(required = false) ForgeConnectionChange body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return connections.update(id,
                body == null ? null : new ForgeConnectionService.Change(body.name(), body.internalNetwork(), body.caPem()),
                RequestActors.of(principal, request));
    }

    @Operation(summary = "Delete forge connection", description = "No target goes with it: an imported repository "
            + "is a target like any other. Signalled VECTI-SEC-034.")
    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteForgeConnection(
            @PathVariable UUID id,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        connections.delete(id, RequestActors.of(principal, request));
    }
}
