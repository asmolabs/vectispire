package com.asmolabs.vectispire.core.gate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.gate.GatePolicy;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.core.gate.persistence.GatePolicies;
import com.asmolabs.vectispire.core.gate.persistence.GatePolicyEntity;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Reading a stored gate policy. The three cases were {@code IssueViewsTest}'s while the conversion sat
 * in {@code issues}; they moved with it to the module that owns the table (decision 0029).
 */
@DisplayName("a stored gate policy, as the verdict and the ticket sweep read it")
class ActiveGatePoliciesTest {

    @Test
    @DisplayName("a policy with no severity written has the severity rule off, not at UNKNOWN")
    void anEmptyThresholdIsOff() {
        assertThat(ActiveGatePolicies.storedPolicy(policy(null)).policy().failOnSeverity()).isNull();
        assertThat(ActiveGatePolicies.storedPolicy(policy("  ")).policy().failOnSeverity()).isNull();
    }

    @Test
    @DisplayName("a severity that is present but unreadable keeps the built-in threshold rather than passing everything")
    void anUnreadableThresholdIsTheBuiltIn() {
        assertThat(ActiveGatePolicies.storedPolicy(policy("catastrophic")).policy().failOnSeverity())
                .isEqualTo(GatePolicy.BUILT_IN.failOnSeverity());
    }

    @Test
    @DisplayName("a readable policy is carried field for field, with its version")
    void aPolicyIsCarried() {
        GatePolicyEntity entity = policy("critical");
        entity.setFailOnKev(false);
        entity.setFixableOnly(true);
        entity.setIncludeTriaged(true);
        entity.setIncludeAiReview(true);
        entity.setFailOnUncoveredLanguages(true);
        entity.setVersion(7);

        var stored = ActiveGatePolicies.storedPolicy(entity);

        assertThat(stored.version()).isEqualTo(7);
        assertThat(stored.policy()).isEqualTo(new GatePolicy(Severity.CRITICAL, false, true, true, true, true));
    }

    @Test
    @DisplayName("keys each active policy by its scope, a global one under id zero")
    void keysByScope() {
        GatePolicyEntity global = policy("high");
        global.setTargetKind("global");
        GatePolicyEntity repository = policy("critical");
        repository.setTargetKind("repository");
        repository.setTargetId(7L);
        GatePolicies policies = mock(GatePolicies.class);
        when(policies.findByIsActiveTrue()).thenReturn(List.of(global, repository));

        // The key is what the sweep and the verdict both spell from an issue's target: a policy keyed
        // otherwise would be looked up by neither, and the issue would silently get the built-in one.
        assertThat(new ActiveGatePolicies(policies).byScope())
                .containsOnlyKeys("global:0", "repository:7");
    }

    private static GatePolicyEntity policy(String failOnSeverity) {
        GatePolicyEntity policy = new GatePolicyEntity();
        policy.setFailOnSeverity(failOnSeverity);
        return policy;
    }
}
