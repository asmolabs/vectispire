package com.asmolabs.zanshin.core.api;

import com.asmolabs.zanshin.common.domain.audit.AuditOperation;
import com.asmolabs.zanshin.common.domain.rules.RuleSet.TriageImpact;
import com.asmolabs.zanshin.common.domain.rules.RuleSet.UploadedFile;
import com.asmolabs.zanshin.core.api.security.ZanshinPrincipal;
import com.asmolabs.zanshin.core.persistence.SemgrepRuleSetEntity;
import com.asmolabs.zanshin.core.repositories.RuleSetSummary;
import com.asmolabs.zanshin.core.services.AuditLogService;
import com.asmolabs.zanshin.core.services.RuleSetService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import org.springframework.security.access.prepost.PreAuthorize;
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
@PreAuthorize("hasAnyRole('SUPERUSER', 'ADMIN')")
public class RuleSetsController {

    private final RuleSetService ruleSets;
    private final AuditLogService audit;

    public RuleSetsController(RuleSetService ruleSets, AuditLogService audit) {
        this.ruleSets = ruleSets;
        this.audit = audit;
    }

    public record Listing(List<RuleSetSummary> ruleSets) {}

    public record UploadRequest(String name, List<UploadedFile> files) {}

    public record Uploaded(Long id, String contentHash, int ruleCount, int fileCount) {}

    public record ActivateRequest(String note) {}

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
            @AuthenticationPrincipal ZanshinPrincipal principal,
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
            @AuthenticationPrincipal ZanshinPrincipal principal,
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
            @AuthenticationPrincipal ZanshinPrincipal principal, HttpServletRequest request) {

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
