package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.scorecard.SecurityGrade;
import com.asmolabs.vectispire.common.domain.scorecard.SecurityScorecard;
import com.asmolabs.vectispire.common.domain.scorecard.SvgBadgeGenerator;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.services.VisibilityService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import com.asmolabs.vectispire.core.services.SecurityScorecardService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.concurrent.TimeUnit;

/**
 * Controller exposing security scorecards, posture grades, and dynamic SVG badges for READMEs.
 */
@Tag(name = "Scorecards", description = "Posture grades, security scorecards and SVG badges")
@RestController
@RequestMapping("/api/v1/scorecards")
public class ScorecardController {

    private final SecurityScorecardService scorecardService;
    private final VisibilityService visibility;

    public ScorecardController(
            SecurityScorecardService scorecardService, VisibilityService visibility) {
        this.scorecardService = scorecardService;
        this.visibility = visibility;
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
    public SecurityScorecard getGlobalScorecard() {
        return scorecardService.getGlobalScorecard();
    }

    /**
     * Public badge endpoint designed for embedding into GitHub/GitLab README.md files.
     */
    @Operation(summary = "Get repository SVG security badge", description = "Renders an SVG shield badge with the current repository security grade.")
    @ApiResponse(responseCode = "200", description = "Dynamic SVG vector badge")
    @GetMapping(value = "/repositories/{repoId}/badge.svg", produces = "image/svg+xml")
    @com.asmolabs.vectispire.core.api.security.OpenToAnonymous
    public ResponseEntity<String> getRepositoryBadge(
            @Parameter(description = "Repository ID", required = true) @PathVariable("repoId") Long repoId) {
        SecurityScorecard scorecard = scorecardService.getRepositoryScorecard(repoId)
                .orElse(null);

        String grade = scorecard != null ? scorecard.grade().getLabel() : "unknown";
        String color = scorecard != null ? scorecard.grade().getBadgeColor() : "#555";

        String svg = SvgBadgeGenerator.generateBadge("security grade", grade, color);

        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(5, TimeUnit.MINUTES).cachePublic())
                .contentType(MediaType.parseMediaType("image/svg+xml"))
                .body(svg);
    }

    private void requireVisible(VectispirePrincipal principal, ScanTarget target) {
        Visibilities.requireVisible(
                target, visibility.of(principal.user().orElse(null), principal.credentialRestriction()));
    }

}
