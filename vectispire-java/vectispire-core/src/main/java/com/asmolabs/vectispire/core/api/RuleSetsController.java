package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.rules.RuleCatalogue;
import com.asmolabs.vectispire.core.services.rules.RuleCatalogueFetcher;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Map;
import com.asmolabs.vectispire.common.domain.rules.RuleSet.TriageImpact;
import com.asmolabs.vectispire.common.domain.rules.RuleSet.UploadedFile;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.persistence.SemgrepRuleSetEntity;
import com.asmolabs.vectispire.core.services.rules.RuleSetAdministrationService;
import com.asmolabs.vectispire.core.services.rules.RuleSetAdministrationService.RuleSetListing;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import com.asmolabs.vectispire.core.api.security.RequiresGovernanceRead;
import com.asmolabs.vectispire.core.api.security.RequiresSecurityLead;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.asmolabs.vectispire.common.domain.rules.RuleCoverage;
import com.asmolabs.vectispire.core.services.rules.RuleCoverageService;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;

/**
 * Uploading Semgrep rule sets, and choosing which one is active.
 *
 * <p><b>Administrators only, and audited.</b> Changing the rule set changes what the scanner
 * looks for, which is the same class of decision as changing a gate policy.
 *
 * <p><b>Upload and activation are two calls, deliberately.</b> Activation is the destructive
 * one: a rule that is not in the new set stops being found, and the next scan resolves its open
 * issues along with their triage. The impact route exists so the screen can say how many, by
 * name, before anybody clicks — and the number it showed is recorded on the activation.
 */
@RestController
@RequestMapping("/api/v1/rule-sets")
@RequiresGovernanceRead
public class RuleSetsController {

    private final RuleSetAdministrationService administration;
    private final RuleCatalogueFetcher fetcher;

    private final RuleCoverageService coverageService;

    public RuleSetsController(
            RuleSetAdministrationService administration, RuleCatalogueFetcher fetcher,
            RuleCoverageService coverageService) {
        this.administration = administration;
        this.fetcher = fetcher;
        this.coverageService = coverageService;
    }

    public record UploadRequest(String name, List<UploadedFile> files) {}

    public record Uploaded(Long id, String contentHash, int ruleCount, int fileCount) {}

    public record ActivateRequest(String note) {}

    /**
     * @param languages how many rule files each holds, so a choice is made on a number rather
     *     than on a name
     * @param categories how many rule files declare each OWASP category. <b>Answers before the
     *     import a question that could only be asked after it.</b> The grid marks a category "not
     *     covered" when no installed rule declares it; knowing what this catalogue holds says
     *     whether that is a limit of the product or an import nobody made
     * @param licence the text at this tag, shown in full. Not summarised: a summary of a licence
     *     is an opinion about a licence
     * @param licenceSha256 echoed back on acceptance, which is what binds the two together
     */
    public record CataloguePreview(
            String upstream,
            String commit,
            String licenceName,
            String licence,
            @JsonProperty("licence_sha256") String licenceSha256,
            Map<String, Integer> languages,
            Map<String, Integer> categories) {}

    public record CatalogueRequest(
            String commit, List<String> languages, @JsonProperty("licence_sha256") String licenceSha256) {}

    @GetMapping
    public RuleSetListing list() {
        return administration.list();
    }

    /**
     * Stores an upload. Does not activate it.
     *
     * <p>The files arrive as JSON rather than multipart, which is not only simpler: there is no
     * archive to extract server-side, and therefore no path traversal to guard against. The
     * names are recorded and never used as paths.
     */
    @RequiresSecurityLead
    @PostMapping
    public Uploaded upload(
            @RequestBody UploadRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        SemgrepRuleSetEntity stored =
                administration.upload(body.files(), body.name(), RequestActors.of(principal, request));
        return new Uploaded(
                stored.getId(), stored.getContentHash(), stored.getRuleCount(), stored.getFileCount());
    }

    /**
     * What this instance can actually see, for the banner the screens raise.
     *
     * <p><b>A fresh deployment scans one pattern in one language and finds nothing</b>, which
     * every other screen renders exactly like code that is clean. This route is what lets them
     * say otherwise — and it names the ecosystems that are uncovered rather than the setting that
     * is unset, because an operator acts on the first and not the second.
     *
     * <p>Open to any account: it describes this instance's own configuration, names no target and
     * discloses no finding. A reader who cannot see a repository can still be told that the
     * deployment does not analyse Go.
     */
    @Operation(summary = "Rule coverage", description = "Whether the installed rules reach the ecosystems in the estate.")
    @ApiResponse(responseCode = "200", description = "Coverage assessed")
    @GetMapping("/coverage")
    public RuleCoverage.Assessment coverage() {
        return coverageService.assess();
    }

    /**
     * What the upstream catalogue holds at a tag, and under what terms.
     *
     * <p><b>Fetched, not summarised from memory.</b> The licence is read from the checkout,
     * because it can change between commits and a stored copy would let somebody accept a text
     * that is not the one they are about to receive.
     *
     * <p>Answering takes a clone, so it is reserved to the role that can act on the answer — the
     * import below is a security lead's — and it is kept ten minutes rather than refetched on each
     * request. The acceptance stays meaningful because the import clones again and checks the
     * licence digest; the preview is only what the screen shows before that.
     */
    @RequiresSecurityLead
    @GetMapping("/catalogue")
    public CataloguePreview catalogue() {
        RuleCatalogueFetcher.Preview preview = fetcher.preview();
        return new CataloguePreview(
                RuleCatalogue.UPSTREAM,
                preview.commit(),
                RuleCatalogue.LICENCE,
                preview.licence(),
                preview.licenceSha256(),
                preview.languages(),
                preview.categories());
    }

    /**
     * Fetches the chosen languages and stores them as a rule set. Does not activate it.
     *
     * <p><b>The acceptance is bound to a licence, not to a checkbox.</b> The digest the caller
     * echoes back must match the one just fetched: without that, "accepted" would mean "clicked
     * a button next to some text at some point", and the text could have changed in between.
     *
     * <p>The audit entry carries the tag, the commit and that digest. A year from now, "which
     * terms did we agree to, and who agreed" has an answer.
     *
     * <p><b>What it does not do is activate.</b> The set lands beside an uploaded one and goes
     * through the same impact preview, because a fetched set can destroy triage exactly as an
     * uploaded one can — more so, since it is larger.
     */
    @RequiresSecurityLead
    @PostMapping("/catalogue")
    public Uploaded fetchCatalogue(
            @RequestBody CatalogueRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        SemgrepRuleSetEntity stored = administration.importCatalogue(
                body.commit(), body.languages(), body.licenceSha256(), RequestActors.of(principal, request));
        return new Uploaded(
                stored.getId(), stored.getContentHash(), stored.getRuleCount(), stored.getFileCount());
    }

    /**
     * What activating this set would cost.
     *
     * <p><b>The screen must show this before offering the button.</b> A rule id enters an issue's
     * fingerprint, so the rules that disappear take their open issues with them — the triage
     * decisions, the justifications, the review dates. Nothing errors, and the dashboard looks
     * better afterwards, which is precisely why it has to be said out loud.
     */
    @GetMapping("/{id}/impact")
    public TriageImpact impact(@PathVariable long id) {
        return administration.impact(id);
    }

    /**
     * Activates a set.
     *
     * <p>{@code note} is what the operator was shown when they confirmed. Recording it is what
     * makes "why did four hundred issues close that afternoon" answerable six months later.
     */
    @RequiresSecurityLead
    @PostMapping("/{id}/activate")
    public Map<String, Object> activate(
            @PathVariable long id,
            @RequestBody(required = false) ActivateRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        String note = body == null || body.note() == null || body.note().isBlank() ? null : body.note().trim();
        SemgrepRuleSetEntity activated = administration.activate(id, note, RequestActors.of(principal, request));
        return Map.of("id", activated.getId(), "contentHash", activated.getContentHash());
    }

    /** Returns to the bundled rules alone. Audited like an activation: it changes coverage. */
    @RequiresSecurityLead
    @PostMapping("/deactivate")
    public Map<String, Object> deactivate(
            @AuthenticationPrincipal VectispirePrincipal principal, HttpServletRequest request) {

        administration.deactivate(RequestActors.of(principal, request));
        return java.util.Collections.singletonMap("active", null);
    }
}
