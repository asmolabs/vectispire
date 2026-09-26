package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.compliance.ScopeCoverage;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.RequiresSecurityLead;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.services.CertifiedScopeService;
import com.asmolabs.vectispire.core.services.access.VisibilityService;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * What the certified scope covers, and how much of it carries current evidence.
 *
 * <h2>The figure this exists to produce is about what is missing</h2>
 *
 * <p><b>A tool measuring its own coverage always reports full coverage.</b> Every other screen
 * here answers a question about the targets somebody registered; a management system has a scope
 * declared in a document, and the two are not the same set. An estate where every target is
 * scanned, made of half the certified assets, reads as a clean result — and nothing inside the
 * database can notice, because the assets that are missing have no row to be missing from.
 *
 * <p>Which is why the scope statement's own asset count is a setting an operator copies from the
 * document. "Your scope names forty assets, this instance holds thirty-one of them" is the
 * sentence an assessment opens with, and it cannot be derived.
 */
@Tag(name = "Certified scope", description = "The ISMS scope, and the evidence covering it")
@RestController
@RequestMapping("/api/v1/compliance/scope")
@RequiresAccount
public class CertifiedScopeController {

    private final CertifiedScopeService scope;
    private final VisibilityService visibility;

    public CertifiedScopeController(CertifiedScopeService scope, VisibilityService visibility) {
        this.scope = scope;
        this.visibility = visibility;
    }

    /**
     * @param statement the scope as its own document words it, empty when nobody has written one
     * @param targets what is marked in scope and the caller may see
     */
    public record ScopeView(String statement, ScopeCoverage coverage, List<TargetRef> targets) {}

    public record TargetRef(String kind, Long id) {}

    @Operation(summary = "The certified scope and its coverage", description = "What the scope covers, how many assets it declares, and how many carry current evidence.")
    @ApiResponse(responseCode = "200", description = "Scope returned")
    @GetMapping
    public ScopeView scope(@AuthenticationPrincipal VectispirePrincipal principal) {
        Visibility allowed = allowed(principal);
        return new ScopeView(
                scope.statement(),
                scope.coverage(allowed),
                scope.inScope(allowed).stream()
                        .map(target -> target instanceof ScanTarget.Repository repository
                                ? new TargetRef("REPOSITORY", repository.id())
                                : new TargetRef("CONTAINER", ((ScanTarget.Container) target).id()))
                        .toList());
    }

    /**
     * Puts one repository in or out of the certified scope.
     *
     * <p>404 rather than 403 on a target the caller may not see, like every other route naming
     * one: a refusal that distinguishes "not yours" from "does not exist" is itself a disclosure.
     */
    @Operation(summary = "Set a repository's scope membership", description = "Marks one repository as inside or outside the certified scope.")
    @ApiResponse(responseCode = "200", description = "Membership set")
    @PutMapping("/repositories/{id}")
    @RequiresSecurityLead
    public ScopeView setRepository(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @PathVariable long id,
            @RequestParam("in_scope") boolean inScope) {
        return set(principal, new ScanTarget.Repository(id), inScope);
    }

    @Operation(summary = "Set an image's scope membership", description = "Marks one container image as inside or outside the certified scope.")
    @ApiResponse(responseCode = "200", description = "Membership set")
    @PutMapping("/containers/{id}")
    @RequiresSecurityLead
    public ScopeView setContainer(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @PathVariable long id,
            @RequestParam("in_scope") boolean inScope) {
        return set(principal, new ScanTarget.Container(id), inScope);
    }

    private ScopeView set(VectispirePrincipal principal, ScanTarget target, boolean inScope) {
        Visibility allowed = allowed(principal);
        Visibilities.requireVisible(target, allowed);
        scope.setInScope(target, inScope);
        return scope(principal);
    }

    private Visibility allowed(VectispirePrincipal principal) {
        return visibility.of(principal.user().orElse(null), principal.credentialRestriction());
    }
}
