package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.gate.GatePolicy;
import com.asmolabs.vectispire.common.domain.gate.GateVerdict;
import com.asmolabs.vectispire.common.domain.gate.PolicyFlag;
import com.asmolabs.vectispire.common.domain.gate.RequestedPolicy;
import com.asmolabs.vectispire.common.domain.gate.SecurityOverview;
import com.asmolabs.vectispire.common.domain.gate.SeverityRequest;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.TrustedProxies;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.services.GateService;
import com.asmolabs.vectispire.core.services.VisibilityService;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.servlet.http.HttpServletRequest;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.paging.RegisterCursor;
import com.asmolabs.vectispire.core.persistence.GateVerdictEntity;
import com.asmolabs.vectispire.core.repositories.GateVerdicts;
import java.time.Instant;
import org.springframework.data.domain.Limit;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * The gate: should this build fail?
 */
@Tag(name = "Gate", description = "Quality Gate policy enforcement and CI/CD build verdicts")
@RestController
@RequestMapping("/api/v1")
@RequiresAccount
public class GateController {

    /** A register is read, not paged through: past a few hundred rows nobody is reading. */
    private static final int MAX_VERDICTS = 500;

    private final GateService gate;
    private final TrustedProxies proxies;
    private final GateVerdicts verdicts;
    private final VisibilityService visibility;

    public GateController(
            GateService gate, VisibilityService visibility, TrustedProxies proxies, GateVerdicts verdicts) {
        this.gate = gate;
        this.proxies = proxies;
        this.verdicts = verdicts;
        this.visibility = visibility;
    }

    /**
     * What the caller <b>actually sent</b>.
     *
     * <p>Every field is boxed, and the difference between {@code null} and a value is the whole
     * point: without it, any caller omitting {@code fail_on_severity} would look like it was
     * asking for the schema's default and would be told its request had been refused, on every
     * single call.
     */
    public record GateRequest(
            @JsonProperty("repository_id") Long repositoryId,
            @JsonProperty("container_id") Long containerId,
            @JsonProperty("fail_on_severity") String failOnSeverity,
            @JsonProperty("fail_on_kev") Boolean failOnKev,
            @JsonProperty("fixable_only") Boolean fixableOnly,
            @JsonProperty("include_triaged") Boolean includeTriaged,
            @JsonProperty("include_ai_review") Boolean includeAiReview) {}

    /**
     * <b>camelCase inside, snake_case outside</b>, and that asymmetry is the contract rather
     * than an oversight. The NestJS gate spread the policy object into the response, so its
     * fields kept the names the domain used, while the response's own fields were written
     * snake_case for the pipelines that read them. No screen consumes this — the client declares
     * the shape and never calls the route — but a pipeline written against the old API does, and
     * it parses by name.
     */
    public record AppliedPolicy(
            String failOnSeverity,
            boolean failOnKev,
            boolean fixableOnly,
            boolean includeTriaged,
            boolean includeAiReview,
            boolean failOnUncoveredLanguages,
            String source,
            Integer version,
            String description) {}

    public record GateResponse(
            boolean passed,
            int evaluated,
            @JsonProperty("counts_by_severity") Map<String, Long> countsBySeverity,
            List<ViolationView> violations,
            AppliedPolicy policy,
            @JsonProperty("ignored_relaxations") List<String> ignoredRelaxations) {}

    /**
     * <b>200 even when the verdict is red</b>: the request succeeded, it is its <em>answer</em>
     * that is negative. A 4xx here would conflate "your repository has vulnerabilities" with
     * "your call is malformed", and a pipeline cannot tell the two apart from a status code.
     */
    @Operation(summary = "Evaluate security quality gate", description = "Evaluates current target vulnerabilities against active or requested gate policy. Returns exit verdict and violations.")
    @ApiResponse(responseCode = "200", description = "Gate verdict evaluated")
    @PostMapping("/gate")
    public GateResponse evaluate(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @RequestBody GateRequest body,
            HttpServletRequest request) {
        if ((body.repositoryId() == null) == (body.containerId() == null)) {
            throw new IllegalArgumentException("Give exactly one of \"repository_id\" or \"container_id\".");
        }

        ScanTarget target = body.repositoryId() != null
                ? new ScanTarget.Repository(body.repositoryId())
                : new ScanTarget.Container(body.containerId());

        // A verdict is a summary of a target's backlog: counts, severities, the identifiers that
        // violate. Answering one for a target the caller may not see hands over most of what the
        // backlog would have said.
        Visibilities.requireVisible(
                target, visibility.of(principal.user().orElse(null), principal.credentialRestriction()));

        // **Recorded, not merely answered.** `evaluateAndRecord` is the only entry point this
        // layer can reach: the evaluation alone is package-private in the service, so a route
        // added later cannot consult the gate without the answer joining the register.
        GateService.Decision decision = gate.evaluateAndRecord(
                target,
                requestedPolicy(body),
                new GateService.Caller(callerName(principal), proxies.clientAddress(request)));
        GateVerdict verdict = decision.verdict();
        GatePolicy policy = decision.policy().policy();

        return new GateResponse(
                verdict.passed(),
                verdict.evaluated(),
                countsByWireName(verdict),
                ViolationView.of(verdict.violations()),
                new AppliedPolicy(
                        policy.failOnSeverity() == null ? null : policy.failOnSeverity().wireName(),
                        policy.flag(PolicyFlag.FAIL_ON_KEV),
                        policy.flag(PolicyFlag.FIXABLE_ONLY),
                        policy.flag(PolicyFlag.INCLUDE_TRIAGED),
                        policy.flag(PolicyFlag.INCLUDE_AI_REVIEW),
                        policy.flag(PolicyFlag.FAIL_ON_UNCOVERED_LANGUAGES),
                        SecurityOverviewView.source(decision.policy().source()),
                        decision.policy().version().orElse(null),
                        decision.policy().describeSource()),
                decision.policy().ignoredRelaxations());
    }

    /** What the caller may read of the gate's answers. */
    public record RegisteredVerdict(
            String id,
            @JsonProperty("target_kind") String targetKind,
            @JsonProperty("target_id") Long targetId,
            boolean passed,
            int evaluated,
            int violations,
            @JsonProperty("counts_by_severity") Map<String, Long> countsBySeverity,
            @JsonProperty("fail_on_severity") String failOnSeverity,
            @JsonProperty("policy_source") String policySource,
            @JsonProperty("policy_version") Long policyVersion,
            @JsonProperty("relaxations_ignored") boolean relaxationsIgnored,
            @JsonProperty("decided_at") Instant decidedAt,
            @JsonProperty("decided_by") String decidedBy) {}

    /**
     * @param passed how many of <em>this page</em> passed, and {@code refused} likewise. Not of
     *     the register: counting the whole of it would mean reading the whole of it, which is the
     *     thing paging exists to avoid
     * @param nextCursor where the next page starts, or null when the read reached the end.
     *     <b>Derived from the rows read, never from the rows returned</b> — see the route
     */
    public record VerdictRegister(
            List<RegisteredVerdict> verdicts,
            long passed,
            long refused,
            @JsonProperty("next_cursor") String nextCursor) {}

    /**
     * The register: what the gate has answered, newest first.
     *
     * <p><b>This route is the whole point of recording verdicts.</b> "Every target passes the
     * gate" is ambiguous between an estate that is clean and a gate that has never stopped
     * anything; a list containing refusals is what separates the two, and it is what an assessor
     * asks for when they want the control demonstrated rather than described.
     *
     * <p><b>The limit bounds what is read, not what is returned.</b> Visibility is applied after
     * the read — by {@code permits}, the single implementation of that question — so a reader
     * restricted to two repositories sees only their rows among the ones this page covers.
     * Narrowing in SQL instead would mean deciding there whose rows to fetch, which is the
     * mistake this codebase has made often enough to refuse making again.
     *
     * <p><b>Which is exactly why the cursor comes from the rows read and not from the rows
     * returned.</b> A restricted reader's page can be empty while the register still holds rows
     * they may see: everything in that window belonged to somebody else. A cursor taken from the
     * visible rows would then be absent, the client would stop, and the register would have
     * quietly ended one page in — for the one class of reader least able to notice.
     *
     * <p>It used to answer the newest hundred and nothing else, with no way to ask for more. That
     * is the right answer for somebody watching a pipeline and the wrong one for an assessment:
     * a busy estate writes a hundred verdicts before lunch, so the page proved yesterday.
     */
    @Operation(summary = "Gate verdict register", description = "The gate's recent answers, newest first, narrowed to what the caller may see.")
    @ApiResponse(responseCode = "200", description = "Register returned")
    @GetMapping("/gate/verdicts")
    public VerdictRegister register(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @RequestParam(required = false, defaultValue = "100") int limit,
            @RequestParam(required = false) String cursor) {

        Visibility allowed = visibility.of(principal.user().orElse(null), principal.credentialRestriction());
        int capped = Math.clamp(limit, 1, MAX_VERDICTS);

        // **An unreadable identifier goes back to the first page**, like an absent cursor. The
        // record promises that an unusable cursor reads as "from the beginning"; letting
        // `UUID.fromString` throw here would make it a 400 on a value the client did not compose —
        // it sent back what the server had given it.
        List<GateVerdictEntity> read = RegisterCursor.parse(cursor)
                .flatMap(from -> uuid(from.id()).map(id -> verdicts.pageAfter(from.at(), id, Limit.of(capped))))
                .orElseGet(() -> verdicts.firstPage(Limit.of(capped)));

        List<RegisteredVerdict> visible = read.stream()
                .filter(row -> allowed.permits(targetOf(row)))
                .map(GateController::view)
                .toList();

        return new VerdictRegister(
                visible,
                visible.stream().filter(RegisteredVerdict::passed).count(),
                visible.stream().filter(view -> !view.passed()).count(),
                nextCursor(read, capped));
    }

    private static Optional<UUID> uuid(String value) {
        try {
            return Optional.of(UUID.fromString(value));
        } catch (IllegalArgumentException unreadable) {
            return Optional.empty();
        }
    }

    /**
     * Where the next page starts, or nothing when this one reached the end.
     *
     * <p>A short read means the register is exhausted — there is nothing after it to point at. A
     * full one means there may be more, and the cursor names the last row <em>read</em>, whether
     * or not the caller was allowed to see it.
     */
    private static String nextCursor(List<GateVerdictEntity> read, int limit) {
        if (read.size() < limit) {
            return null;
        }
        GateVerdictEntity last = read.getLast();
        return new RegisterCursor(last.getDecidedAt(), last.getId().toString()).encoded();
    }

    private static ScanTarget targetOf(GateVerdictEntity row) {
        return row.getRepoId() != null
                ? new ScanTarget.Repository(row.getRepoId())
                : new ScanTarget.Container(row.getContainerId());
    }

    private static RegisteredVerdict view(GateVerdictEntity row) {
        boolean isRepository = row.getRepoId() != null;
        return new RegisteredVerdict(
                row.getId().toString(),
                isRepository ? "REPOSITORY" : "CONTAINER",
                isRepository ? row.getRepoId() : row.getContainerId(),
                row.isPassed(),
                row.getEvaluated(),
                row.getViolations(),
                Map.of(
                        "critical", row.getCriticalCount(),
                        "high", row.getHighCount(),
                        "medium", row.getMediumCount(),
                        "low", row.getLowCount()),
                row.getFailOnSeverity(),
                row.getPolicySource(),
                row.getPolicyVersion(),
                row.isRelaxationsIgnored(),
                row.getDecidedAt(),
                row.getDecidedBy());
    }

    /**
     * Who to attribute a verdict to.
     *
     * <p>An agent's name rather than its key, an account's username rather than its id: the
     * register is read by a person months later, and a row naming {@code 41} tells them nothing.
     */
    private static String callerName(VectispirePrincipal principal) {
        return principal.user()
                .map(user -> user.getUsername())
                .or(() -> principal.agent().map(agent -> "agent:" + agent.getName()))
                .orElse(null);
    }

    /** Every target's posture — what the security screen shows. */
    @Operation(summary = "Get global security posture overview", description = "Returns aggregate posture and gate statuses for all monitored targets.")
    @ApiResponse(responseCode = "200", description = "Security overview retrieved")
    @GetMapping("/security/overview")
    public SecurityOverviewView overview(@AuthenticationPrincipal VectispirePrincipal principal) {
        return SecurityOverviewView.of(
                gate.overview(visibility.of(principal.user().orElse(null), principal.credentialRestriction())));
    }

    private static Map<String, Long> countsByWireName(GateVerdict verdict) {
        return verdict.countsBySeverity().entrySet().stream()
                .collect(java.util.stream.Collectors.toMap(entry -> entry.getKey().wireName(), Map.Entry::getValue));
    }

    private static RequestedPolicy requestedPolicy(GateRequest body) {
        RequestedPolicy requested = RequestedPolicy.none();
        if (body.failOnSeverity() != null) {
            requested = requested.with(severityRequest(body.failOnSeverity()));
        }
        requested = withFlag(requested, PolicyFlag.FAIL_ON_KEV, body.failOnKev());
        requested = withFlag(requested, PolicyFlag.FIXABLE_ONLY, body.fixableOnly());
        requested = withFlag(requested, PolicyFlag.INCLUDE_TRIAGED, body.includeTriaged());
        requested = withFlag(requested, PolicyFlag.INCLUDE_AI_REVIEW, body.includeAiReview());
        return requested;
    }

    /**
     * {@code "none"} disables the threshold; anything else is one.
     *
     * <p>An unreadable severity is a threshold of {@code UNKNOWN}, which ranks last and would
     * fail nothing. Refusing it is the only safe reading: a pipeline that typed "hgh" must be
     * told, not quietly given a gate that passes everything.
     */
    private static SeverityRequest severityRequest(String value) {
        if ("none".equalsIgnoreCase(value)) {
            return new SeverityRequest.Disabled();
        }
        Severity severity = Severity.of(value);
        if (severity == Severity.UNKNOWN) {
            throw new IllegalArgumentException("Unknown severity: \"" + value + "\".");
        }
        return new SeverityRequest.Threshold(severity);
    }

    private static RequestedPolicy withFlag(RequestedPolicy requested, PolicyFlag flag, Boolean value) {
        return value == null ? requested : requested.with(flag, value);
    }
}
