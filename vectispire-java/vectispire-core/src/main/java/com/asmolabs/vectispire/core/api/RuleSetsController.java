package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.rules.RuleCatalogue;
import com.asmolabs.vectispire.core.services.RuleCatalogueFetcher;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Map;
import java.util.Set;
import org.springframework.web.bind.annotation.RequestParam;
import com.asmolabs.vectispire.common.domain.rules.RuleSet.TriageImpact;
import com.asmolabs.vectispire.common.domain.rules.RuleSet.UploadedFile;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.persistence.SemgrepRuleSetEntity;
import com.asmolabs.vectispire.core.repositories.RuleSetSummary;
import com.asmolabs.vectispire.core.services.AuditLogService;
import com.asmolabs.vectispire.core.services.RuleSetService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.NoSuchElementException;
import com.asmolabs.vectispire.core.api.security.RequiresSecurityLead;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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
@RequiresSecurityLead
public class RuleSetsController {

    private final RuleSetService ruleSets;
    private final RuleCatalogueFetcher fetcher;
    private final AuditLogService audit;

    public RuleSetsController(
            RuleSetService ruleSets, RuleCatalogueFetcher fetcher, AuditLogService audit) {
        this.ruleSets = ruleSets;
        this.fetcher = fetcher;
        this.audit = audit;
    }

    public record Listing(List<RuleSetSummary> ruleSets) {}

    public record UploadRequest(String name, List<UploadedFile> files) {}

    public record Uploaded(Long id, String contentHash, int ruleCount, int fileCount) {}

    public record ActivateRequest(String note) {}

    /**
     * @param languages how many rule files each holds, so a choice is made on a number rather
     *     than on a name
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
            Map<String, Integer> languages) {}

    public record CatalogueRequest(
            String commit, List<String> languages, @JsonProperty("licence_sha256") String licenceSha256) {}

    @GetMapping
    public Listing list() {
        return new Listing(ruleSets.list());
    }

    /**
     * Stores an upload. Does not activate it.
     *
     * <p>The files arrive as JSON rather than multipart, which is not only simpler: there is no
     * archive to extract server-side, and therefore no path traversal to guard against. The
     * names are recorded and never used as paths.
     */
    @PostMapping
    public Uploaded upload(
            @RequestBody UploadRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        String actor = principal.user().map(user -> user.getUsername()).orElse(null);
        SemgrepRuleSetEntity stored = ruleSets.store(
                body.files() == null ? List.of() : body.files(), body.name(), actor);

        audit.record(new AuditLogService.Record(
                AuditOperation.RULE_SET_UPLOADED,
                String.valueOf(stored.getId()),
                "Rule set \"" + stored.getName() + "\" uploaded: " + stored.getFileCount() + " files, "
                        + stored.getRuleCount() + " rules.",
                actor,
                request.getRemoteAddr(),
                request.getHeader("User-Agent")));

        return new Uploaded(
                stored.getId(), stored.getContentHash(), stored.getRuleCount(), stored.getFileCount());
    }

    /**
     * What the upstream catalogue holds at a tag, and under what terms.
     *
     * <p><b>Fetched, not summarised from memory.</b> The licence is read from the checkout,
     * because it can change between commits and a stored copy would let somebody accept a text
     * that is not the one they are about to receive.
     *
     * <p>This clones the repository to answer, which is not cheap. It is an administrator
     * action taken rarely, and the alternative — trusting a cached description — is exactly the
     * thing that makes an acceptance meaningless.
     */
    @GetMapping("/catalogue")
    public CataloguePreview catalogue() {
        RuleCatalogueFetcher.Fetched fetched = fetcher.fetch();
        return new CataloguePreview(
                RuleCatalogue.UPSTREAM,
                fetched.commit(),
                RuleCatalogue.LICENCE,
                fetched.contents().licence(),
                fetched.licenceSha256(),
                fetched.contents().languages());
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
    @PostMapping("/catalogue")
    public Uploaded fetchCatalogue(
            @RequestBody CatalogueRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        RuleCatalogue.requireCommit(body.commit());
        RuleCatalogueFetcher.Fetched fetched = fetcher.fetch();

        // **Both must still match.** The upstream is a moving branch, so between reading the
        // licence and accepting it the head can advance. Refusing is the only honest answer: an
        // acceptance that silently applied to a different commit would be worth nothing, and
        // this is the one place where "it probably did not change" is not good enough.
        if (!fetched.commit().equalsIgnoreCase(body.commit())) {
            throw new IllegalArgumentException(
                    "The upstream moved between the preview and this request: you read " + body.commit()
                            + ", it is now " + fetched.commit() + ". Read the catalogue again.");
        }
        if (!fetched.licenceSha256().equals(body.licenceSha256())) {
            throw new IllegalArgumentException(
                    "The licence changed between the preview and this request. Read it again before accepting: "
                            + "what you agreed to is not what this commit carries.");
        }

        Set<String> languages = body.languages() == null ? Set.of() : Set.copyOf(body.languages());
        List<UploadedFile> files = RuleCatalogue.select(fetched.contents(), languages);

        String actor = principal.user().map(user -> user.getUsername()).orElse(null);
        SemgrepRuleSetEntity stored =
                ruleSets.store(files, RuleCatalogue.nameFor(fetched.commit(), languages), actor);

        audit.record(new AuditLogService.Record(
                AuditOperation.RULE_SET_UPLOADED,
                String.valueOf(stored.getId()),
                "Fetched " + RuleCatalogue.UPSTREAM + " at commit " + fetched.commit() + ", languages " + String.join(", ", new java.util.TreeSet<>(languages)) + ": "
                        + stored.getRuleCount() + " rules. Licence " + RuleCatalogue.LICENCE
                        + " accepted, sha256 " + fetched.licenceSha256() + ".",
                actor,
                request.getRemoteAddr(),
                request.getHeader("User-Agent")));

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
        return ruleSets.impactOf(
                ruleSets.byId(id).orElseThrow(() -> new NoSuchElementException("No rule set with id " + id + ".")));
    }

    /**
     * Activates a set.
     *
     * <p>{@code note} is what the operator was shown when they confirmed. Recording it is what
     * makes "why did four hundred issues close that afternoon" answerable six months later.
     */
    @PostMapping("/{id}/activate")
    public Map<String, Object> activate(
            @PathVariable long id,
            @RequestBody(required = false) ActivateRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        String note = body == null || body.note() == null || body.note().isBlank() ? null : body.note().trim();
        SemgrepRuleSetEntity activated = ruleSets.activate(id, note);

        audit.record(new AuditLogService.Record(
                AuditOperation.RULE_SET_ACTIVATED,
                String.valueOf(activated.getId()),
                "Rule set \"" + activated.getName() + "\" activated. "
                        + (activated.getActivationNote() == null ? "No impact recorded." : activated.getActivationNote()),
                principal.user().map(user -> user.getUsername()).orElse(null),
                request.getRemoteAddr(),
                request.getHeader("User-Agent")));

        return Map.of("id", activated.getId(), "contentHash", activated.getContentHash());
    }

    /** Returns to the bundled rules alone. Audited like an activation: it changes coverage. */
    @PostMapping("/deactivate")
    public Map<String, Object> deactivate(
            @AuthenticationPrincipal VectispirePrincipal principal, HttpServletRequest request) {

        ruleSets.deactivateAll();
        audit.record(new AuditLogService.Record(
                AuditOperation.RULE_SET_DEACTIVATED,
                "all",
                "Uploaded rule sets deactivated; scans fall back to the bundled rules.",
                principal.user().map(user -> user.getUsername()).orElse(null),
                request.getRemoteAddr(),
                request.getHeader("User-Agent")));

        return java.util.Collections.singletonMap("active", null);
    }
}
