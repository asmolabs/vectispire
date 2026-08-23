package com.asmolabs.zanshin.core.api;

import com.asmolabs.zanshin.common.domain.scorecard.SecurityGrade;
import com.asmolabs.zanshin.common.domain.scorecard.SecurityScorecard;
import com.asmolabs.zanshin.common.domain.scorecard.SvgBadgeGenerator;
import com.asmolabs.zanshin.core.api.security.RequiresAccount;
import com.asmolabs.zanshin.core.services.SecurityScorecardService;
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
@RestController
@RequestMapping("/api/v1/scorecards")
public class ScorecardController {

    private final SecurityScorecardService scorecardService;

    public ScorecardController(SecurityScorecardService scorecardService) {
        this.scorecardService = scorecardService;
    }

    @GetMapping("/repositories/{repoId}")
    @RequiresAccount
    public SecurityScorecard getRepositoryScorecard(@PathVariable("repoId") Long repoId) {
        return scorecardService.getRepositoryScorecard(repoId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Repository not found: " + repoId));
    }

    @GetMapping("/containers/{containerId}")
    @RequiresAccount
    public SecurityScorecard getContainerScorecard(@PathVariable("containerId") Long containerId) {
        return scorecardService.getContainerScorecard(containerId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Container not found: " + containerId));
    }

    @GetMapping("/global")
    @RequiresAccount
    public SecurityScorecard getGlobalScorecard() {
        return scorecardService.getGlobalScorecard();
    }

    /**
     * Public badge endpoint designed for embedding into GitHub/GitLab README.md files.
     */
    @GetMapping(value = "/repositories/{repoId}/badge.svg", produces = "image/svg+xml")
    @com.asmolabs.zanshin.core.api.security.OpenToAnonymous
    public ResponseEntity<String> getRepositoryBadge(@PathVariable("repoId") Long repoId) {
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
}
