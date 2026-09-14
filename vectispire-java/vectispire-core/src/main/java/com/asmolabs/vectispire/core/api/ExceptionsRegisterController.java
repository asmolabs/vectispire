package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.RequiresSecurityLead;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.services.ExceptionsRegisterService;
import com.asmolabs.vectispire.core.services.IssueTriageService;
import com.asmolabs.vectispire.core.services.VisibilityService;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.time.Instant;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * What somebody decided not to fix, and under what terms.
 *
 * <h2>Why this is a screen of its own</h2>
 *
 * <p><b>It is the question an assessor asks first, and the one a dashboard never answers.</b>
 * Every other view describes what the estate contains. This one describes what was argued away —
 * and a green backlog means two very different things depending on which of the two produced it.
 *
 * <p>The data has existed all along: every triage decision is written, with its author, its
 * justification and its expiry, and a second person has to approve one when four-eyes is on. What
 * was missing is the view — so the register could only be read one issue at a time, by somebody
 * who already knew which issue to open.
 *
 * <h2>What it shows, and what it deliberately does not</h2>
 *
 * <p>Two kinds of decision: the exemptions granted, and the ones awaiting approval. Not the
 * fixes. An issue closed because it was repaired is not an exception, and folding the two
 * together would bury the handful of rows that matter under every resolution the estate has ever
 * made.
 *
 * <p><b>A lapsed exemption is flagged rather than dropped.</b> One that expired last week and has
 * not been renewed is the most interesting row in the register: the risk was accepted for a
 * period, the period is over, and nobody has looked since.
 */
@Tag(name = "Exceptions", description = "The register of risk acceptances and dismissals")
@RestController
@RequestMapping("/api/v1/exceptions")
@RequiresAccount
public class ExceptionsRegisterController {

    private final ExceptionsRegisterService register;
    private final IssueTriageService triage;
    private final Issues issues;
    private final VisibilityService visibility;

    public ExceptionsRegisterController(
            ExceptionsRegisterService register,
            IssueTriageService triage,
            Issues issues,
            VisibilityService visibility) {
        this.register = register;
        this.triage = triage;
        this.issues = issues;
        this.visibility = visibility;
    }

    /**
     * What a reviewer concluded, and the date if they extended it.
     *
     * @param newExpiry required when extending, ignored otherwise
     */
    public record ReviewRequest(
            IssueTriageService.ReviewOutcome outcome,
            String comment,
            @JsonProperty("new_expiry") Instant newExpiry) {}

    /**
     * Records that somebody revisited one exception.
     *
     * <p><b>A confirmation is the call that matters, and it changes nothing.</b> Every other write
     * in this product exists because something moved; periodic review is the one control that is
     * performed correctly by leaving a decision exactly as it was — and so the one that left no
     * evidence at all. "Granted in January, expires in December" reads identically whether it was
     * revisited every quarter or opened by nobody since.
     *
     * <p>A security lead, like granting the exception: withdrawing one puts an issue back in front
     * of a gate, and confirming one is a statement about risk somebody has to own.
     */
    @Operation(summary = "Review an exception", description = "Confirm, extend or revoke one exception, and record that it was looked at.")
    @ApiResponse(responseCode = "200", description = "Review recorded")
    @ApiResponse(responseCode = "400", description = "The issue carries no exception, or an extension names no date")
    @PostMapping("/{issueId}/reviews")
    @RequiresSecurityLead
    public ExceptionsRegisterService.Register review(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @PathVariable long issueId,
            @RequestBody ReviewRequest body) {

        Visibility allowed = visibility.of(principal.user().orElse(null), principal.credentialRestriction());
        // 404 rather than 403, like everywhere else here: a restricted reader must not learn that
        // an issue exists by being refused it.
        Visibilities.requireVisible(issues.findById(issueId).orElse(null), allowed);

        triage.review(
                issueId,
                body.outcome(),
                body.comment(),
                principal.user().map(user -> user.getUsername()).orElse(null),
                body.newExpiry());

        return register.register(200, allowed);
    }

    @Operation(summary = "The exceptions register", description = "Risk acceptances and dismissals, newest first, narrowed to what the caller may see.")
    @ApiResponse(responseCode = "200", description = "Register returned")
    @GetMapping
    public ExceptionsRegisterService.Register register(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @RequestParam(required = false, defaultValue = "200") int limit) {

        return register.register(
                limit, visibility.of(principal.user().orElse(null), principal.credentialRestriction()));
    }
}
