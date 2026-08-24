package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.gate.GatePolicy;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.api.security.RequiresSecurityLead;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.persistence.GatePolicyEntity;
import com.asmolabs.vectispire.core.services.AuditLogService;
import com.asmolabs.vectispire.core.services.GateService;
import com.asmolabs.vectispire.core.services.GateService.PolicyScope;
import com.asmolabs.vectispire.core.services.IssueViews;
import com.asmolabs.vectispire.core.services.TargetNaming;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.NoSuchElementException;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * Writing the rules a pipeline is judged against.
 *
 * <p><b>The table has been read since the first release and written by nothing.</b> Every
 * install therefore ran on {@link GatePolicy#BUILT_IN}, the per-target scope was unreachable,
 * and the versioning the schema carries had no versions to keep. The verdict route,
 * {@code POST /api/v1/gate}, has always resolved target over global over built-in — this is the
 * half that lets somebody put something there.
 *
 * <p><b>Administrators only, and separately from {@link GateController}.</b> Reading a verdict
 * is an ordinary account's business, and a pipeline holding an API key asks for one on every
 * build; deciding what fails a build is not the same act, and mixing the two behind one class
 * annotation is how the strict marker ends up being the weaker of the two.
 */
@RestController
@RequestMapping("/api/v1/gate/policies")
@RequiresSecurityLead
public class GatePoliciesController {

    private final GateService gate;
    private final TargetNaming names;
    private final AuditLogService audit;

    public GatePoliciesController(GateService gate, TargetNaming names, AuditLogService audit) {
        this.gate = gate;
        this.names = names;
        this.audit = audit;
    }

    /**
     * @param failOnSeverity the threshold, or {@code null} for "the severity rule is off". The
     *     difference is not cosmetic: {@code null} is the policy that blocks on actively
     *     exploited findings alone, and reading it as a threshold nobody set would fail every
     *     build instead
     * @param targetName resolved here so the screen does not need one request per policy — and
     *     so a policy left behind by a deleted target is visible as such rather than as a bare
     *     number
     */
    public record PolicyView(
            String kind,
            @JsonProperty("target_id") Long targetId,
            @JsonProperty("target_name") String targetName,
            int version,
            @JsonProperty("fail_on_severity") String failOnSeverity,
            @JsonProperty("fail_on_kev") boolean failOnKev,
            @JsonProperty("fixable_only") boolean fixableOnly,
            @JsonProperty("include_triaged") boolean includeTriaged,
            @JsonProperty("include_ai_review") boolean includeAiReview,
            String note,
            @JsonProperty("created_by") String createdBy,
            @JsonProperty("created_at") String createdAt) {}

    /**
     * @param builtIn what applies where nothing is stored. Sent with the list because the screen
     *     has to show the operator what they are departing from: a form pre-filled with the
     *     defaults of the code, next to a table of overrides, is the only place the difference
     *     between "not set" and "set to the same thing" is visible
     */
    public record PoliciesResponse(
            List<PolicyView> policies, @JsonProperty("built_in") PolicyView builtIn) {}

    /**
     * @param failOnSeverity a severity, or {@code "none"} to switch the rule off. Absent is
     *     refused rather than defaulted: this route replaces a policy wholesale, and a field
     *     nobody sent would silently reinstate the built-in threshold under a version number
     *     that says somebody chose it
     */
    public record PolicyRequest(
            @JsonProperty("fail_on_severity") String failOnSeverity,
            @JsonProperty("fail_on_kev") Boolean failOnKev,
            @JsonProperty("fixable_only") Boolean fixableOnly,
            @JsonProperty("include_triaged") Boolean includeTriaged,
            @JsonProperty("include_ai_review") Boolean includeAiReview,
            String note) {}

    @GetMapping
    public PoliciesResponse list() {
        TargetNaming.Names all = names.all();

        List<PolicyView> stored = new ArrayList<>(gate.storedPolicies().stream()
                .map(policy -> view(policy, all))
                .sorted(Comparator.comparing(PolicyView::kind).thenComparing(
                        view -> view.targetName() == null ? "" : view.targetName()))
                .toList());

        return new PoliciesResponse(stored, builtInView());
    }

    /** The global policy: what every target inherits unless it has one of its own. */
    @PutMapping("/global")
    public PolicyView storeGlobal(
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request,
            @RequestBody PolicyRequest body) {

        return store(PolicyScope.global(), "the global policy", principal, request, body);
    }

    @PutMapping("/{kind}/{id}")
    public PolicyView storeForTarget(
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request,
            @PathVariable String kind,
            @PathVariable long id,
            @RequestBody PolicyRequest body) {

        PolicyScope scope = PolicyScope.of(target(kind, id));
        return store(scope, kind + " " + id, principal, request, body);
    }

    /**
     * Removes an override, so the target inherits the global policy again.
     *
     * <p>404 when there was nothing to remove: answering 204 would tell an operator their
     * override is gone whether or not it ever existed, which is the same sentence for "done"
     * and for "you were looking at a stale screen".
     */
    @DeleteMapping("/{kind}/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void clear(
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request,
            @PathVariable String kind,
            @PathVariable long id) {

        PolicyScope scope = PolicyScope.of(target(kind, id));
        if (!gate.clear(scope)) {
            throw new NoSuchElementException("No policy stored for " + kind + " " + id + ".");
        }
        record(principal, request, scope, "Gate policy removed; the target inherits again.");
    }

    private PolicyView store(
            PolicyScope scope,
            String what,
            VectispirePrincipal principal,
            HttpServletRequest request,
            PolicyRequest body) {

        GatePolicy policy = policyOf(body);
        GatePolicyEntity stored = gate.store(
                scope, policy, body.note(), principal == null ? null : principal.getName());

        record(
                principal,
                request,
                scope,
                "Gate policy for " + what + " set to version " + stored.getVersion() + ": "
                        + describe(policy) + ".");

        return view(stored, names.all());
    }

    /**
     * <b>Every field is read, none is defaulted from what is already stored.</b> A partial
     * update would make "leave this alone" and "set it to false" the same request, and the two
     * differ by a build that fails.
     */
    private static GatePolicy policyOf(PolicyRequest body) {
        return new GatePolicy(
                threshold(body.failOnSeverity()),
                required(body.failOnKev(), "fail_on_kev"),
                required(body.fixableOnly(), "fixable_only"),
                required(body.includeTriaged(), "include_triaged"),
                required(body.includeAiReview(), "include_ai_review"));
    }

    private static boolean required(Boolean value, String field) {
        if (value == null) {
            throw new IllegalArgumentException("\"" + field + "\" is required.");
        }
        return value;
    }

    /**
     * {@code "none"} switches the severity rule off; anything else is a threshold.
     *
     * <p>An unreadable severity is refused rather than stored, for the reason the verdict route
     * gives: {@code Severity.of} answers {@code UNKNOWN}, which ranks last, and a policy written
     * from a typo would fail every build — or, read the other way round, pass everything.
     */
    private static Severity threshold(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(
                    "\"fail_on_severity\" is required — a severity, or \"none\" to switch the rule off.");
        }
        if ("none".equalsIgnoreCase(value.trim())) {
            return null;
        }
        Severity severity = Severity.of(value);
        if (severity == Severity.UNKNOWN) {
            throw new IllegalArgumentException("Unknown severity: \"" + value + "\".");
        }
        return severity;
    }

    private static ScanTarget target(String kind, long id) {
        return switch (kind) {
            case "repository" -> new ScanTarget.Repository(id);
            case "container" -> new ScanTarget.Container(id);
            default -> throw new IllegalArgumentException(
                    "Unknown target kind: \"" + kind + "\". Use repository or container.");
        };
    }

    private static PolicyView view(GatePolicyEntity policy, TargetNaming.Names names) {
        boolean global = "global".equals(policy.getTargetKind());
        GatePolicy resolved = IssueViews.storedPolicy(policy).policy();

        return new PolicyView(
                policy.getTargetKind(),
                global ? null : policy.getTargetId(),
                global ? null : nameOf(policy, names),
                policy.getVersion(),
                resolved.failOnSeverity() == null ? null : resolved.failOnSeverity().wireName(),
                resolved.failOnKev(),
                resolved.fixableOnly(),
                resolved.includeTriaged(),
                resolved.includeAiReview(),
                policy.getNote(),
                policy.getCreatedBy(),
                policy.getCreatedAt() == null ? null : policy.getCreatedAt().toString());
    }

    private static String nameOf(GatePolicyEntity policy, TargetNaming.Names names) {
        return "container".equals(policy.getTargetKind())
                ? names.of(null, policy.getTargetId())
                : names.of(policy.getTargetId(), null);
    }

    /** The code's own defaults, shown as a policy so the screen can compare like with like. */
    private static PolicyView builtInView() {
        GatePolicy policy = GatePolicy.BUILT_IN;
        return new PolicyView(
                "built_in",
                null,
                null,
                0,
                policy.failOnSeverity() == null ? null : policy.failOnSeverity().wireName(),
                policy.failOnKev(),
                policy.fixableOnly(),
                policy.includeTriaged(),
                policy.includeAiReview(),
                null,
                null,
                null);
    }

    private static String describe(GatePolicy policy) {
        List<String> parts = new ArrayList<>();
        parts.add("fail on "
                + (policy.failOnSeverity() == null ? "no severity" : policy.failOnSeverity().wireName()));
        if (policy.failOnKev()) {
            parts.add("fail on actively exploited");
        }
        if (policy.fixableOnly()) {
            parts.add("fixable only");
        }
        if (policy.includeTriaged()) {
            parts.add("triaged findings counted");
        }
        if (policy.includeAiReview()) {
            parts.add("model review counted");
        }
        return String.join(", ", parts);
    }

    /**
     * <b>Audited, because it decides what fails a build.</b> {@code GATE_POLICY_UPDATED} has
     * been in the enum since the beginning with nothing writing it; loosening a threshold is
     * exactly the change somebody has to be able to find afterwards.
     */
    private void record(
            VectispirePrincipal principal, HttpServletRequest request, PolicyScope scope, String description) {

        audit.record(new AuditLogService.Record(
                AuditOperation.GATE_POLICY_UPDATED,
                scope.kind() + ":" + scope.id(),
                description,
                principal == null ? null : principal.getName(),
                request.getRemoteAddr(),
                request.getHeader("User-Agent")));
    }
}
