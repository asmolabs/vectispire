package com.asmolabs.vectispire.core.forges.web;

import com.asmolabs.vectispire.core.access.web.security.RequestActors;
import com.asmolabs.vectispire.core.access.web.security.RequiresAdministrator;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.forges.ForgeDiscoveryService;
import com.asmolabs.vectispire.core.forges.ForgeDiscoveryView;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * A forge connection's discoveries (decision 0037 §3). Administrators only, as for the connection: a discovery lists
 * repositories no grant covers yet, and a reader with a project grant would learn the names of the whole
 * organisation. Integration keys are not accepted in v1. The service queues and reads; this maps the requests.
 */
@Tag(name = "Forge connections", description = "Read-only credentials to GitHub and GitLab, for discovering repositories")
@RestController
@RequestMapping("/api/v1/forge-connections/{connectionId}/discoveries")
@RequiresAdministrator
public class ForgeDiscoveriesController {

    private final ForgeDiscoveryService discoveries;

    public ForgeDiscoveriesController(ForgeDiscoveryService discoveries) {
        this.discoveries = discoveries;
    }

    @Operation(summary = "Discover forge repositories", description = "Queues a discovery of the connection and answers "
            + "at once, 202 with the run — pending — to poll. A control-plane instance claims it under a lease and lists "
            + "the namespaces, then the repositories with their metadata (GitLab: the groups and projects the token is a "
            + "member of, min_access_level 10, membership=true), through the outbound guard and the connection's pinned "
            + "CA, the next page followed on the connection's own origin only. Bounds: thirty minutes, twenty thousand "
            + "repositories, a rate-limit wait of up to a minute inside the run — past any of them the run ends partial. "
            + "404 when no connection has that id; 409 forge-discovery-in-progress with discoveryId while one is pending "
            + "or running; 409 forge-discovery-unsupported for a GitHub connection, whose listing arrives with lot D4. "
            + "A queued discovery is audited FORGE_DISCOVERY_REQUESTED; a refused request records nothing.")
    @PostMapping
    @ResponseStatus(HttpStatus.ACCEPTED)
    public ForgeDiscoveryView requestForgeDiscovery(
            @PathVariable UUID connectionId,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return discoveries.request(connectionId, RequestActors.of(principal, request));
    }

    @Operation(summary = "List forge discoveries", description = "The connection's last fifty discoveries, newest first.")
    @GetMapping
    public List<ForgeDiscoveryView> listForgeDiscoveries(@PathVariable UUID connectionId) {
        return discoveries.list(connectionId);
    }

    @Operation(summary = "Read forge discovery", description = "What a screen polls: state (pending, running, completed, "
            + "partial, failed), reason for a partial or failed one (time_bound, repository_bound, rate_limited; "
            + "token_rejected, destination_blocked, cross_origin_page, forge_unavailable, forge_refused, "
            + "connection_unusable, unsupported, executor_lost, internal_error), the counters — namespaces and "
            + "repositories seen, requests made, seconds waited on rate limits, when a limit that ended it lifts — and "
            + "once it ended newCount, changedCount and goneCount; goneCount is null unless it completed.")
    @GetMapping("/{discoveryId}")
    public ForgeDiscoveryView getForgeDiscovery(@PathVariable UUID connectionId, @PathVariable long discoveryId) {
        return discoveries.get(connectionId, discoveryId);
    }

    @Operation(summary = "List discovered repositories", description = "The repositories a discovery listed (change=all, "
            + "the default), first listed (new), found renamed or moved, re-branched, archived, unarchived or back "
            + "(changed, with changeSummary), or no longer listed (gone — a completed discovery only, 400 otherwise), by "
            + "full path, limit 1 to 500 (100) from an offset that is a multiple of it. A value the forge did not give "
            + "is null — unknown, never zero.")
    @GetMapping("/{discoveryId}/repositories")
    public ForgeDiscoveryService.RepositoryPage listDiscoveredRepositories(
            @PathVariable UUID connectionId,
            @PathVariable long discoveryId,
            @RequestParam(required = false) String change,
            @RequestParam(required = false) Integer limit,
            @RequestParam(required = false) Integer offset) {
        return discoveries.repositories(connectionId, discoveryId, change, limit, offset);
    }
}
