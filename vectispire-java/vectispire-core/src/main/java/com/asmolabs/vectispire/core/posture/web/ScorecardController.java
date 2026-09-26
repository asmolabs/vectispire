package com.asmolabs.vectispire.core.posture.web;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.scorecard.SecurityScorecard;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.access.web.security.RequestActors;
import com.asmolabs.vectispire.core.access.web.security.RequiresAccount;
import com.asmolabs.vectispire.core.access.web.security.RequiresWriteAccount;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.access.web.security.Visibilities;
import com.asmolabs.vectispire.core.posture.ScorecardBadgeService;
import com.asmolabs.vectispire.core.posture.SecurityScorecardService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import java.util.concurrent.TimeUnit;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Controller exposing security scorecards, posture grades, and dynamic SVG badges for READMEs.
 */
@Tag(name = "Scorecards", description = "Posture grades, security scorecards and SVG badges")
@RestController
@RequestMapping("/api/v1/scorecards")
public class ScorecardController {

    private final SecurityScorecardService scorecardService;
    private final VisibilityService visibility;
    private final ScorecardBadgeService badges;

    public ScorecardController(
            SecurityScorecardService scorecardService, VisibilityService visibility, ScorecardBadgeService badges) {
        this.scorecardService = scorecardService;
        this.visibility = visibility;
        this.badges = badges;
    }

    @Operation(summary = "Get repository scorecard", description = "Calculates security grade (A+ to F), risk posture, and metric breakdown for a repository.")
    @ApiResponse(responseCode = "200", description = "Repository scorecard retrieved successfully")
    @GetMapping("/repositories/{repoId}")
    @RequiresAccount
    public SecurityScorecard getRepositoryScorecard(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @Parameter(description = "Repository ID", required = true) @PathVariable("repoId") Long repoId) {
        // A scorecard is a target's posture in a number, and the number is the interesting part
        // to somebody who was not given the target: it says how exposed a neighbouring team is.
        requireVisible(principal, new ScanTarget.Repository(repoId));
        return scorecardService.getRepositoryScorecard(repoId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Repository not found: " + repoId));
    }

    @Operation(summary = "Get container scorecard", description = "Calculates security grade and risk posture for a container image.")
    @ApiResponse(responseCode = "200", description = "Container scorecard retrieved successfully")
    @GetMapping("/containers/{containerId}")
    @RequiresAccount
    public SecurityScorecard getContainerScorecard(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @Parameter(description = "Container ID", required = true) @PathVariable("containerId") Long containerId) {
        requireVisible(principal, new ScanTarget.Container(containerId));
        return scorecardService.getContainerScorecard(containerId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Container not found: " + containerId));
    }

    @Operation(summary = "Get global scorecard", description = "Calculates cross-organizational aggregate security posture grade.")
    @ApiResponse(responseCode = "200", description = "Global scorecard retrieved successfully")
    @GetMapping("/global")
    @RequiresAccount
    public SecurityScorecard getGlobalScorecard(@AuthenticationPrincipal VectispirePrincipal principal) {
        return scorecardService.getGlobalScorecard(
                visibility.of(principal.user().orElse(null), principal.credentialRestriction()));
    }

    /** @param url what to paste into a README, absent when no badge is published */
    public record BadgeState(boolean published, String token, String url) {}

    /**
     * The badge of a repository somebody chose to publish.
     *
     * <p><b>Anonymous by necessity, and named by a token for exactly that reason.</b> A README's
     * image is fetched by a browser that has no session, so whatever identifies the repository in
     * this URL is readable by everyone who sees the README — and by everyone who guesses.
     *
     * <p>This route used to take the repository's {@code Long} id. Walking 1..N therefore returned
     * the security grade of every repository in the installation, across accounts and teams, with
     * no {@code Visibility} consulted anywhere — the single route in the product that served
     * business data outside the model the rest of it is built on. It was also an existence oracle:
     * a repository that was not there answered {@code unknown} while one that was answered a
     * grade, which is the distinction {@link Visibilities#requireVisible} exists to erase.
     *
     * <p><b>404 for an unknown token and for a revoked one alike.</b> Telling them apart would say
     * that a repository once had a badge, which is a fact about the estate.
     */
    @Operation(summary = "Get a published SVG security badge",
            description = "Renders the SVG shield of the repository this badge token was issued for.")
    @ApiResponse(responseCode = "200", description = "Dynamic SVG vector badge")
    @ApiResponse(responseCode = "404", description = "No badge is published under this token")
    @GetMapping(value = "/badges/{token}.svg", produces = "image/svg+xml")
    @com.asmolabs.vectispire.core.access.web.security.OpenToAnonymous
    public ResponseEntity<String> getPublishedBadge(
            @Parameter(description = "Badge token", required = true) @PathVariable("token") String token) {

        String svg = badges.publishedSvg(token)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "No badge under this token."));

        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(5, TimeUnit.MINUTES).cachePublic())
                .contentType(MediaType.parseMediaType("image/svg+xml"))
                .body(svg);
    }

    /** Whether a badge is published for this repository, and under which URL. */
    @Operation(summary = "Read a repository's badge state")
    @GetMapping("/repositories/{repoId}/badge")
    @RequiresAccount
    public BadgeState badgeState(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @Parameter(description = "Repository ID", required = true) @PathVariable("repoId") Long repoId) {

        return stateOf(badges.state(repoId, allowed(principal))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Repository not found: " + repoId)));
    }

    /**
     * Publishes this repository's grade, and hands back the URL to paste.
     *
     * <p><b>Publishing is a decision, so it is a call somebody makes.</b> It says that this
     * repository's posture may be read by anyone holding the link, which is not something to
     * inherit from the fact that a badge route exists.
     *
     * <p>Idempotent — see {@link ScorecardBadgeService#publish} — and audited only when it did
     * publish, so the log holds one entry per decision rather than one per click.
     */
    @Operation(summary = "Publish a repository's security badge")
    @PostMapping("/repositories/{repoId}/badge")
    @RequiresWriteAccount
    public BadgeState publishBadge(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @Parameter(description = "Repository ID", required = true) @PathVariable("repoId") Long repoId,
            HttpServletRequest request) {

        return stateOf(badges.publish(repoId, allowed(principal), RequestActors.of(principal, request))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Repository not found: " + repoId)));
    }

    /** Revokes the badge. Every README carrying the old URL starts answering 404. */
    @Operation(summary = "Revoke a repository's security badge")
    @DeleteMapping("/repositories/{repoId}/badge")
    @RequiresWriteAccount
    public BadgeState revokeBadge(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @Parameter(description = "Repository ID", required = true) @PathVariable("repoId") Long repoId,
            HttpServletRequest request) {

        return stateOf(badges.revoke(repoId, allowed(principal), RequestActors.of(principal, request))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Repository not found: " + repoId)));
    }

    private static BadgeState stateOf(ScorecardBadgeService.Badge badge) {
        String token = badge.token();
        return token == null
                ? new BadgeState(false, null, null)
                : new BadgeState(true, token, "/api/v1/scorecards/badges/" + token + ".svg");
    }

    private void requireVisible(VectispirePrincipal principal, ScanTarget target) {
        Visibilities.requireVisible(target, allowed(principal));
    }

    private Visibility allowed(VectispirePrincipal principal) {
        return visibility.of(principal.user().orElse(null), principal.credentialRestriction());
    }

}
