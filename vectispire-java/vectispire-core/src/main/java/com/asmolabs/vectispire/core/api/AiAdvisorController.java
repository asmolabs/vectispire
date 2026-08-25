package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.aireview.AiVulnerabilityAdvice;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.services.VisibilityService;
import com.asmolabs.vectispire.core.services.AiReviewService;
import java.util.List;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * AI Fix & Exploit Advisor endpoints for contextual vulnerability explanation and remediation.
 */
@RestController
@RequestMapping("/api/v1/ai-advisor")
@RequiresAccount
public class AiAdvisorController {

    private final AiReviewService aiReviewService;
    private final Issues issuesRepo;
    private final VisibilityService visibility;

    public AiAdvisorController(
            AiReviewService aiReviewService, Issues issuesRepo, VisibilityService visibility) {
        this.aiReviewService = aiReviewService;
        this.issuesRepo = issuesRepo;
        this.visibility = visibility;
    }

    @GetMapping("/status")
    public Map<String, Object> getStatus() {
        return Map.of(
                "enabled", aiReviewService.isEnabled(),
                "selectedModel", aiReviewService.selectedModel(),
                "ollamaUrl", aiReviewService.ollamaUrl(),
                "availableModels", aiReviewService.availableModels());
    }

    @PostMapping("/explain/issue/{issueId}")
    public AiVulnerabilityAdvice explainIssue(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @PathVariable Long issueId) {
        IssueEntity issue = issuesRepo.findById(issueId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Issue not found: " + issueId));

        // The principal was already on this signature and was already unused — the route took
        // an identifier, found the row and explained it, whoever asked. An explanation names the
        // package, the file and the fix, which is the finding itself in prose.
        Visibilities.requireVisible(
                issue, visibility.of(principal.user().orElse(null), principal.credentialRestriction()));

        return aiReviewService.explainVulnerability(issue);
    }

    @PostMapping("/explain/cve/{cveId}")
    public AiVulnerabilityAdvice explainCve(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @PathVariable String cveId,
            @RequestParam(required = false) String packageName,
            @RequestParam(required = false) String currentVersion,
            @RequestParam(required = false) String fixVersion,
            @RequestParam(required = false) String reachability) {

        List<IssueEntity> matched = issuesRepo.findByIdentifier(cveId);
        if (!matched.isEmpty()) {
            return aiReviewService.explainVulnerability(matched.get(0));
        }

        return AiVulnerabilityAdvice.generateDeterministic(
                cveId,
                packageName,
                currentVersion,
                fixVersion,
                reachability != null ? reachability : "UNKNOWN",
                cveId.toUpperCase().contains("2021-44228") || cveId.toUpperCase().contains("2024-3094"),
                0.75);
    }
}
