package com.asmolabs.vectispire.core.gate;

import com.asmolabs.vectispire.common.domain.gate.GatePolicy;
import com.asmolabs.vectispire.common.domain.gate.PolicyResolution.StoredPolicy;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.core.gate.persistence.GatePolicies;
import com.asmolabs.vectispire.core.gate.persistence.GatePolicyEntity;
import java.util.HashMap;
import java.util.Map;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The stored gate policies in force, read the one way the verdict reads them.
 *
 * <p><b>Why a class of its own, and why here.</b> Two passes evaluate the gate: the verdict a
 * pipeline asks for, and the ticket sweep, which opens a ticket for an issue only if the policy of
 * its scope would fail on it. Each read the policy table itself and built the same map, and the
 * conversion from a row to a policy — where an empty threshold means "rule off" — sat in {@code
 * issues}' {@code IssueViews}, below the module that owns the table. The store is {@code gate}'s
 * (decision 0029): the sweep asks it, and the conversion is written once, beside the rows.
 */
@Service
public class ActiveGatePolicies {

    private final GatePolicies policies;

    public ActiveGatePolicies(GatePolicies policies) {
        this.policies = policies;
    }

    /**
     * Every active policy, keyed {@code kind:id} — {@code global:0}, {@code repository:7}, {@code
     * container:3} — the scope as a caller spells it from an issue's target.
     */
    @Transactional(readOnly = true)
    public Map<String, StoredPolicy> byScope() {
        Map<String, StoredPolicy> byScope = new HashMap<>();
        for (GatePolicyEntity policy : policies.findByIsActiveTrue()) {
            byScope.put(
                    policy.getTargetKind() + ":" + (policy.getTargetId() == null ? 0 : policy.getTargetId()),
                    storedPolicy(policy));
        }
        return byScope;
    }

    /** A stored gate policy, with the version the API reports back to a pipeline. */
    static StoredPolicy storedPolicy(GatePolicyEntity policy) {
        return new StoredPolicy(
                new GatePolicy(
                        thresholdOf(policy.getFailOnSeverity()),
                        policy.getFailOnKev(),
                        policy.getFixableOnly(),
                        policy.getIncludeTriaged(),
                        policy.getIncludeAiReview(),
                        policy.getFailOnUncoveredLanguages()),
                policy.getVersion());
    }

    /**
     * <b>An empty column stays {@code null}, and {@code null} is not {@code UNKNOWN}.</b>
     *
     * <p>No severity written means the severity rule is off — blocking on KEV alone is a
     * policy somebody will want. {@code Severity.of} answers {@code UNKNOWN} for a missing
     * value, and {@code UNKNOWN} ranks below every real severity: {@code isAtLeast(UNKNOWN)}
     * holds for every issue, so the policy that switched the rule <em>off</em> would have
     * failed every build instead, and the verdict would have named a threshold nobody set.
     *
     * <p>A value that is present and unreadable is the other case and keeps the safe reading:
     * the rule stays on, at the built-in threshold. A row written by a later version, or by
     * hand, must not turn into a gate that passes everything.
     */
    private static Severity thresholdOf(String stored) {
        if (stored == null || stored.isBlank()) {
            return null;
        }
        Severity severity = Severity.of(stored);
        return severity == Severity.UNKNOWN ? GatePolicy.BUILT_IN.failOnSeverity() : severity;
    }
}
