package com.asmolabs.zanshin.core.api;

import com.asmolabs.zanshin.common.domain.gate.GatePolicy;
import com.asmolabs.zanshin.common.domain.gate.GateVerdict;
import com.asmolabs.zanshin.common.domain.gate.PolicyFlag;
import com.asmolabs.zanshin.common.domain.gate.RequestedPolicy;
import com.asmolabs.zanshin.common.domain.gate.SecurityOverview;
import com.asmolabs.zanshin.common.domain.gate.SeverityRequest;
import com.asmolabs.zanshin.common.domain.issues.Severity;
import com.asmolabs.zanshin.common.domain.targets.ScanTarget;
import com.asmolabs.zanshin.core.api.security.RequiresAccount;
import com.asmolabs.zanshin.core.services.GateService;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The gate: should this build fail?
 *
 * <p>{@code POST} rather than {@code GET} for the verdict, because the request carries a body:
 * the requested policy. It can only <b>tighten</b> the stored one, and refused relaxations come
 * back rather than being ignored in silence.
 */
@RestController
@RequestMapping("/api/v1")
@RequiresAccount
public class GateController {

    private final GateService gate;

    public GateController(GateService gate) {
        this.gate = gate;
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

    public record AppliedPolicy(
            @JsonProperty("fail_on_severity") String failOnSeverity,
            @JsonProperty("fail_on_kev") boolean failOnKev,
            @JsonProperty("fixable_only") boolean fixableOnly,
            @JsonProperty("include_triaged") boolean includeTriaged,
            @JsonProperty("include_ai_review") boolean includeAiReview,
            String source,
            Integer version,
            String description) {}

    public record GateResponse(
            boolean passed,
            int evaluated,
            @JsonProperty("counts_by_severity") Map<String, Long> countsBySeverity,
            List<GateVerdict.Violation> violations,
            AppliedPolicy policy,
            @JsonProperty("ignored_relaxations") List<String> ignoredRelaxations) {}

    /**
     * <b>200 even when the verdict is red</b>: the request succeeded, it is its <em>answer</em>
     * that is negative. A 4xx here would conflate "your repository has vulnerabilities" with
     * "your call is malformed", and a pipeline cannot tell the two apart from a status code.
     */
    @PostMapping("/gate")
    public GateResponse evaluate(@RequestBody GateRequest body) {
        if ((body.repositoryId() == null) == (body.containerId() == null)) {
            throw new IllegalArgumentException("Give exactly one of \"repository_id\" or \"container_id\".");
        }

        ScanTarget target = body.repositoryId() != null
                ? new ScanTarget.Repository(body.repositoryId())
                : new ScanTarget.Container(body.containerId());

        GateService.Decision decision = gate.evaluate(target, requestedPolicy(body));
        GateVerdict verdict = decision.verdict();
        GatePolicy policy = decision.policy().policy();

        return new GateResponse(
                verdict.passed(),
                verdict.evaluated(),
                countsByWireName(verdict),
                verdict.violations(),
                new AppliedPolicy(
                        policy.failOnSeverity() == null ? null : policy.failOnSeverity().wireName(),
                        policy.flag(PolicyFlag.FAIL_ON_KEV),
                        policy.flag(PolicyFlag.FIXABLE_ONLY),
                        policy.flag(PolicyFlag.INCLUDE_TRIAGED),
                        policy.flag(PolicyFlag.INCLUDE_AI_REVIEW),
                        decision.policy().source().name().toLowerCase(java.util.Locale.ROOT),
                        decision.policy().version().orElse(null),
                        decision.policy().describeSource()),
                decision.policy().ignoredRelaxations());
    }

    /** Every target's posture — what the security screen shows. */
    @GetMapping("/security/overview")
    public SecurityOverview.Overview overview() {
        return gate.overview();
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
