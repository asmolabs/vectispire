package com.asmolabs.vectispire.core.services.issues;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.dependencies.Directness;
import com.asmolabs.vectispire.common.domain.exports.ExportableIssue.FixState;
import com.asmolabs.vectispire.common.domain.gate.GatePolicy;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.core.persistence.GatePolicyEntity;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.repositories.IssueRows;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The conversions every gate, ticket and export reads a stored row through.
 *
 * <p>Each one resolves an ambiguity in one direction on purpose, and each wrong direction is
 * silent: an unreadable triage read as a dismissal drops the issue from every gate, an empty
 * threshold read as {@code UNKNOWN} fails every build, a missing directness read as transitive
 * writes a confident wrong answer into a ticket. None of it had a test of its own.
 */
@DisplayName("reading a stored issue for a domain rule")
class IssueViewsTest {

    @Test
    @DisplayName("a triage nobody recognizes stays in the backlog, from an entity and from a projection alike")
    void anUnreadableTriageIsUnderReview() {
        IssueEntity issue = issue();
        issue.setTriageStatus("dismissed-by-a-later-version");

        assertThat(IssueViews.forGate(issue).triage()).isEqualTo(TriageStatus.UNDER_REVIEW);
        assertThat(IssueViews.forExport(issue).triageStatus()).isEqualTo(TriageStatus.UNDER_REVIEW);
        assertThat(IssueViews.forGate(row("dismissed-by-a-later-version")).triage()).isEqualTo(TriageStatus.UNDER_REVIEW);
    }

    @Test
    @DisplayName("a triage that is readable is kept as written")
    void aReadableTriageIsKept() {
        IssueEntity issue = issue();
        issue.setTriageStatus("not_affected");

        assertThat(IssueViews.forGate(issue).triage()).isEqualTo(TriageStatus.NOT_AFFECTED);
        assertThat(IssueViews.forGate(row("not_affected")).triage()).isEqualTo(TriageStatus.NOT_AFFECTED);
    }

    @Test
    @DisplayName("the entity and the projection give the gate the same view of the same row")
    void bothInputsAgree() {
        IssueEntity issue = issue();
        issue.setTriageStatus("affected");

        assertThat(IssueViews.forGate(row("affected"))).isEqualTo(IssueViews.forGate(issue));
    }

    @Test
    @DisplayName("an unknown directness stays unknown rather than becoming transitive")
    void directnessIsNotGuessed() {
        IssueEntity issue = issue();

        issue.setIsDirectDependency(null);
        assertThat(IssueViews.forTicket(issue).directness()).isEqualTo(Directness.UNKNOWN);
        assertThat(IssueViews.forExport(issue).directness()).isEqualTo(Directness.UNKNOWN);

        issue.setIsDirectDependency(false);
        assertThat(IssueViews.forTicket(issue).directness()).isEqualTo(Directness.TRANSITIVE);
        issue.setIsDirectDependency(true);
        assertThat(IssueViews.forExport(issue).directness()).isEqualTo(Directness.DIRECT);
    }

    @Test
    @DisplayName("an unreadable fix state is unknown, never fixed — fixed is the claim that closes a ticket")
    void anUnreadableFixStateIsUnknown() {
        IssueEntity issue = issue();
        issue.setFixState("patched-maybe");

        assertThat(IssueViews.forTicket(issue).fixState()).isEqualTo(FixState.UNKNOWN);
        assertThat(IssueViews.forExport(issue).fixState()).isEqualTo(FixState.UNKNOWN);
    }

    @Test
    @DisplayName("only a resolved row exports as resolved, and only an open one counts as open for the gate")
    void stateIsReadStrictly() {
        IssueEntity issue = issue();
        assertThat(IssueViews.forGate(issue).open()).isTrue();
        assertThat(IssueViews.forExport(issue).resolved()).isFalse();

        issue.setState("resolved");
        assertThat(IssueViews.forGate(issue).open()).isFalse();
        assertThat(IssueViews.forExport(issue).resolved()).isTrue();
    }

    @Test
    @DisplayName("a policy with no severity written has the severity rule off, not at UNKNOWN")
    void anEmptyThresholdIsOff() {
        assertThat(IssueViews.storedPolicy(policy(null)).policy().failOnSeverity()).isNull();
        assertThat(IssueViews.storedPolicy(policy("  ")).policy().failOnSeverity()).isNull();
    }

    @Test
    @DisplayName("a severity that is present but unreadable keeps the built-in threshold rather than passing everything")
    void anUnreadableThresholdIsTheBuiltIn() {
        assertThat(IssueViews.storedPolicy(policy("catastrophic")).policy().failOnSeverity())
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

        var stored = IssueViews.storedPolicy(entity);

        assertThat(stored.version()).isEqualTo(7);
        assertThat(stored.policy()).isEqualTo(new GatePolicy(Severity.CRITICAL, false, true, true, true, true));
    }

    private static IssueEntity issue() {
        IssueEntity issue = new IssueEntity();
        issue.setId(42L);
        issue.setState("open");
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setSeverity("high");
        issue.setIdentifier("CVE-2026-0001");
        issue.setPackageName("lodash");
        issue.setFixVersions("4.17.22");
        issue.setIsKev(true);
        return issue;
    }

    private static IssueRows.GateRow row(String triage) {
        return new IssueRows.GateRow(
                42L, 1L, null, "open", "vulnerability", "high", "CVE-2026-0001", "lodash", "4.17.22", true, triage);
    }

    private static GatePolicyEntity policy(String failOnSeverity) {
        GatePolicyEntity policy = new GatePolicyEntity();
        policy.setFailOnSeverity(failOnSeverity);
        return policy;
    }
}
