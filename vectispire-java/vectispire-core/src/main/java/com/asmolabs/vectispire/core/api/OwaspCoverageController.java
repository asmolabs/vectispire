package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.services.OwaspCoverageService;
import com.asmolabs.vectispire.core.services.VisibilityService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The Top 10, answered by rule rather than by a model.
 *
 * <h2>Why it sits beside the report and does not replace it</h2>
 *
 * <p>The report on {@code /repositories/{id}/owasp-review} is written by the configured model: it
 * reads the backlog and produces prose, which is the part a person wants and no rule engine
 * writes. <b>It is not evidence.</b> An assessor cannot accept a document whose content depends on
 * which model answered, and a category green last quarter and amber this one has told them nothing
 * about the estate.
 *
 * <p>This route answers the same ten questions from the finding's type alone. Every mapping is one
 * sentence somebody can check, every line carries why it says what it says, and where no rule
 * applies the answer is <em>not covered</em> rather than a guess.
 *
 * <h2>Three of ten, and that is the finding</h2>
 *
 * <p>Seven categories are covered by no scanner here. A grid showing them green would be claiming
 * a clean bill of health over an examination that never happened — which is the same defect the
 * freshness window removed from the compliance matrix and the banner removed from the quality
 * screen, in the one place an auditor looks first.
 */
@Tag(name = "OWASP coverage", description = "The Top 10 by rule, with what this deployment cannot see")
@RestController
@RequestMapping("/api/v1/owasp/coverage")
@RequiresAccount
public class OwaspCoverageController {

    private final OwaspCoverageService coverage;
    private final VisibilityService visibility;

    public OwaspCoverageController(OwaspCoverageService coverage, VisibilityService visibility) {
        this.coverage = coverage;
        this.visibility = visibility;
    }

    @Operation(summary = "OWASP Top 10 coverage", description = "Each category's state — findings, nothing found, unmeasured, or covered by no scanner here.")
    @ApiResponse(responseCode = "200", description = "Grid returned")
    @GetMapping
    public OwaspCoverage.Grid grid(@AuthenticationPrincipal VectispirePrincipal principal) {
        return coverage.grid(
                visibility.of(principal.user().orElse(null), principal.credentialRestriction()));
    }
}
