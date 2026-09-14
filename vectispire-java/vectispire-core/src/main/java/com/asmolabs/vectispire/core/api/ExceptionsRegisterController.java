package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.services.ExceptionsRegisterService;
import com.asmolabs.vectispire.core.services.VisibilityService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
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
    private final VisibilityService visibility;

    public ExceptionsRegisterController(ExceptionsRegisterService register, VisibilityService visibility) {
        this.register = register;
        this.visibility = visibility;
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
