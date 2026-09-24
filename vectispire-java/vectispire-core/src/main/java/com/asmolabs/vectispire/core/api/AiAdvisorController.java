package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.aireview.AiVulnerabilityAdvice;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.RequiresWriteAccount;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.services.AiAdvisorService;
import com.asmolabs.vectispire.core.services.AiReviewService;
import com.asmolabs.vectispire.core.services.VisibilityService;
import java.util.Map;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * AI Fix & Exploit Advisor endpoints for contextual vulnerability explanation and remediation.
 */
@RestController
@RequestMapping("/api/v1/ai-advisor")
@RequiresAccount
public class AiAdvisorController {

    private final AiReviewService aiReviewService;
    private final AiAdvisorService advisor;
    private final VisibilityService visibility;

    public AiAdvisorController(
            AiReviewService aiReviewService, AiAdvisorService advisor, VisibilityService visibility) {
        this.aiReviewService = aiReviewService;
        this.advisor = advisor;
        this.visibility = visibility;
    }

    @GetMapping("/status")
    public Map<String, Object> getStatus() {
        // **The Ollama URL is deliberately absent.** It was published here to every signed-in
        // account, and an internal service address is not a secret but it is a starting point:
        // it names a host and a port on the network the control plane sits on, to a caller who
        // may have been given nothing else. The screen needs to know whether the advisor works
        // and which model answers — never where it lives.
        return Map.of(
                "enabled", aiReviewService.isEnabled(),
                "selectedModel", aiReviewService.selectedModel(),
                "availableModels", aiReviewService.availableModels());
    }

    @RequiresWriteAccount
    @PostMapping("/explain/issue/{issueId}")
    public AiVulnerabilityAdvice explainIssue(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @PathVariable Long issueId) {
        // The principal was already on this signature and was already unused — the route took
        // an identifier, found the row and explained it, whoever asked. An explanation names the
        // package, the file and the fix, which is the finding itself in prose. Absent and hidden
        // answer alike, in the service.
        return advisor.explainIssue(
                issueId, visibility.of(principal.user().orElse(null), principal.credentialRestriction()));
    }

    @RequiresWriteAccount
    @PostMapping("/explain/cve/{cveId}")
    public AiVulnerabilityAdvice explainCve(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @PathVariable String cveId,
            @RequestParam(required = false) String packageName,
            @RequestParam(required = false) String currentVersion,
            @RequestParam(required = false) String fixVersion,
            @RequestParam(required = false) String reachability) {

        // Narrowed before anything is read, so that a CVE present only in a target the caller was
        // not given gets exactly the answer a CVE present nowhere gets — see `AiAdvisorService`.
        return advisor.explainCve(
                cveId,
                packageName,
                currentVersion,
                fixVersion,
                reachability,
                visibility.of(principal.user().orElse(null), principal.credentialRestriction()));
    }
}
