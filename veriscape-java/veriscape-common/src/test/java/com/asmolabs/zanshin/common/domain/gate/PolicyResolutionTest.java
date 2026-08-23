package com.asmolabs.zanshin.common.domain.gate;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.zanshin.common.domain.issues.Severity;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("policy resolution")
class PolicyResolutionTest {

    private static final PolicyResolution.StoredPolicy GLOBAL =
            new PolicyResolution.StoredPolicy(new GatePolicy(Severity.MEDIUM, true, false, false, false), 4);
    private static final PolicyResolution.StoredPolicy FOR_TARGET =
            new PolicyResolution.StoredPolicy(new GatePolicy(Severity.LOW, true, false, false, false), 9);

    @Test
    @DisplayName("a target's policy replaces the global one entirely")
    void targetBeatsGlobal() {
        PolicyResolution.ResolvedPolicy resolved = PolicyResolution.resolve(
                PolicyResolution.PolicyLookup.of(FOR_TARGET, GLOBAL),
                RequestedPolicy.none(),
                PolicyResolution.Scope.TARGET);

        assertThat(resolved.policy()).isEqualTo(FOR_TARGET.policy());
        assertThat(resolved.source()).isEqualTo(PolicyResolution.Source.TARGET);
        assertThat(resolved.version()).contains(9);
    }

    @Test
    @DisplayName("without one of its own, a target falls back to the global policy")
    void fallsBackToGlobal() {
        PolicyResolution.ResolvedPolicy resolved = PolicyResolution.resolve(
                PolicyResolution.PolicyLookup.of(null, GLOBAL),
                RequestedPolicy.none(),
                PolicyResolution.Scope.TARGET);

        assertThat(resolved.source()).isEqualTo(PolicyResolution.Source.GLOBAL);
        assertThat(resolved.describeSource()).isEqualTo("the global policy v4");
    }

    @Test
    @DisplayName("a question about the organization ignores any target policy")
    void globalScopeIgnoresTargetPolicy() {
        PolicyResolution.ResolvedPolicy resolved = PolicyResolution.resolve(
                PolicyResolution.PolicyLookup.of(FOR_TARGET, GLOBAL),
                RequestedPolicy.none(),
                PolicyResolution.Scope.GLOBAL);

        assertThat(resolved.source()).isEqualTo(PolicyResolution.Source.GLOBAL);
        assertThat(resolved.policy()).isEqualTo(GLOBAL.policy());
    }

    @Test
    @DisplayName("with nothing stored, the built-in policy applies and carries no version")
    void fallsBackToBuiltIn() {
        PolicyResolution.ResolvedPolicy resolved = PolicyResolution.resolve(
                new PolicyResolution.PolicyLookup(Optional.empty(), Optional.empty()),
                RequestedPolicy.none(),
                PolicyResolution.Scope.TARGET);

        assertThat(resolved.policy()).isEqualTo(GatePolicy.BUILT_IN);
        assertThat(resolved.source()).isEqualTo(PolicyResolution.Source.BUILT_IN);
        assertThat(resolved.version()).isEmpty();
    }

    @Test
    @DisplayName("a caller's request tightens the resolved policy and reports what it could not")
    void requestTightensAndReports() {
        // The provenance is part of the answer: a pipeline that fails needs to know whose rules
        // these are, or its first reflex is to loosen its own settings and change nothing.
        PolicyResolution.ResolvedPolicy resolved = PolicyResolution.resolve(
                PolicyResolution.PolicyLookup.of(null, GLOBAL),
                RequestedPolicy.none()
                        .with(new SeverityRequest.Threshold(Severity.CRITICAL))
                        .with(PolicyFlag.INCLUDE_TRIAGED, true),
                PolicyResolution.Scope.TARGET);

        assertThat(resolved.policy().failOnSeverity()).isEqualTo(Severity.MEDIUM);
        assertThat(resolved.policy().includeTriaged()).isTrue();
        assertThat(resolved.ignoredRelaxations()).containsExactly("fail_on_severity");
    }
}
