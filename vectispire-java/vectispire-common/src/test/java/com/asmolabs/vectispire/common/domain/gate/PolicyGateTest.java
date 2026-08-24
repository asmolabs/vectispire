package com.asmolabs.zanshin.common.domain.gate;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.zanshin.common.domain.issues.FindingType;
import com.asmolabs.zanshin.common.domain.issues.Severity;
import com.asmolabs.zanshin.common.domain.issues.TriageStatus;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("policy gate")
class PolicyGateTest {

    private static GateIssue issue(long id, FindingType type, Severity severity, TriageStatus triage) {
        return new GateIssue(id, true, type, severity, "CVE-" + id, "pkg", null, false, triage);
    }

    @Nested
    @DisplayName("what is evaluated at all")
    class Considered {

        @Test
        @DisplayName("quality findings never fail a build, whatever the policy asks")
        void qualityNeverBlocks() {
            // Every flag on, including the ones that widen the evaluated set. Quality must
            // still be absent: there is no option, and this test is what keeps it that way.
            GatePolicy everything = new GatePolicy(Severity.NEGLIGIBLE, true, false, true, true);

            GateVerdict verdict = PolicyGate.evaluate(
                    List.of(issue(1, FindingType.QUALITY, Severity.CRITICAL, null)), everything);

            assertThat(verdict.passed()).isTrue();
            assertThat(verdict.evaluated()).isZero();
        }

        @Test
        @DisplayName("AI review findings are excluded by default and countable on request")
        void aiReviewIsOptIn() {
            List<GateIssue> findings = List.of(issue(1, FindingType.AI_REVIEW, Severity.CRITICAL, null));

            assertThat(PolicyGate.evaluate(findings, GatePolicy.BUILT_IN).passed()).isTrue();

            GatePolicy including = GatePolicy.BUILT_IN.with(PolicyFlag.INCLUDE_AI_REVIEW, true);
            assertThat(PolicyGate.evaluate(findings, including).passed()).isFalse();
        }

        @Test
        @DisplayName("a settled issue does not fail a build, unless triage is included")
        void settledIssuesAreExcluded() {
            List<GateIssue> findings =
                    List.of(issue(1, FindingType.VULNERABILITY, Severity.CRITICAL, TriageStatus.NOT_AFFECTED));

            assertThat(PolicyGate.evaluate(findings, GatePolicy.BUILT_IN).passed()).isTrue();
            assertThat(PolicyGate.evaluate(findings, GatePolicy.BUILT_IN.with(PolicyFlag.INCLUDE_TRIAGED, true))
                            .passed())
                    .isFalse();
        }

        @Test
        @DisplayName("an issue still under review keeps counting")
        void underReviewStillCounts() {
            // Somebody looking at it is not somebody having decided about it.
            List<GateIssue> findings =
                    List.of(issue(1, FindingType.VULNERABILITY, Severity.CRITICAL, TriageStatus.UNDER_REVIEW));

            assertThat(PolicyGate.evaluate(findings, GatePolicy.BUILT_IN).passed()).isFalse();
        }

        @Test
        @DisplayName("a closed issue never counts")
        void closedIssuesAreExcluded() {
            GateIssue closed = new GateIssue(1, false, FindingType.VULNERABILITY, Severity.CRITICAL, "CVE-1", "pkg", null, true, null);

            assertThat(PolicyGate.evaluate(List.of(closed), GatePolicy.BUILT_IN).passed()).isTrue();
        }

        @Test
        @DisplayName("fixable-only skips what has no published fix")
        void fixableOnlySkipsUnfixable() {
            GateIssue unfixable = new GateIssue(1, true, FindingType.VULNERABILITY, Severity.CRITICAL, "CVE-1", "pkg", "  ", false, null);
            GatePolicy policy = GatePolicy.BUILT_IN.with(PolicyFlag.FIXABLE_ONLY, true);

            // Blank counts as absent: a scanner writing "" for "no fix" must not be read as
            // having published one.
            assertThat(PolicyGate.evaluate(List.of(unfixable), policy).passed()).isTrue();
        }
    }

    @Nested
    @DisplayName("the verdict")
    class Verdict {

        @Test
        @DisplayName("KEV fails the build whatever the severity")
        void kevOutranksSeverity() {
            // A medium exploited in the wild outranks a critical that never has been.
            GateIssue kev = new GateIssue(1, true, FindingType.VULNERABILITY, Severity.MEDIUM, "CVE-1", "pkg", null, true, null);

            GateVerdict verdict = PolicyGate.evaluate(List.of(kev), GatePolicy.BUILT_IN);

            assertThat(verdict.passed()).isFalse();
            assertThat(verdict.violations()).singleElement().extracting(GateVerdict.Violation::rule)
                    .isEqualTo(GateVerdict.Rule.KEV);
        }

        @Test
        @DisplayName("reports one violation per issue, not one per rule tripped")
        void oneViolationPerIssue() {
            // A critical KEV trips both rules. Reporting both would double the output without
            // adding an action.
            GateIssue both = new GateIssue(1, true, FindingType.VULNERABILITY, Severity.CRITICAL, "CVE-1", "pkg", null, true, null);

            assertThat(PolicyGate.evaluate(List.of(both), GatePolicy.BUILT_IN).violations()).hasSize(1);
        }

        @Test
        @DisplayName("unknown severity ranks below low and does not fail a build")
        void unknownIsNotTheWorstCase() {
            // The OSV backend returns it whenever an advisory has no normalized severity.
            // Ranking it worst would fail every build on that backend.
            GateIssue unknown = issue(1, FindingType.VULNERABILITY, Severity.UNKNOWN, null);

            assertThat(PolicyGate.evaluate(List.of(unknown), GatePolicy.BUILT_IN).passed()).isTrue();
        }

        @Test
        @DisplayName("counts by severity cover what was evaluated, not what violated")
        void countsCoverTheEvaluatedSet() {
            GateVerdict verdict = PolicyGate.evaluate(
                    List.of(
                            issue(1, FindingType.VULNERABILITY, Severity.CRITICAL, null),
                            issue(2, FindingType.VULNERABILITY, Severity.LOW, null),
                            issue(3, FindingType.VULNERABILITY, Severity.LOW, null)),
                    GatePolicy.BUILT_IN);

            assertThat(verdict.evaluated()).isEqualTo(3);
            assertThat(verdict.countsBySeverity())
                    .containsEntry(Severity.CRITICAL, 1L)
                    .containsEntry(Severity.LOW, 2L);
            assertThat(verdict.violations()).hasSize(1);
        }

        @Test
        @DisplayName("a null threshold disables the severity rule without disabling KEV")
        void nullThresholdKeepsKev() {
            GatePolicy kevOnly = new GatePolicy(null, true, false, false, false);
            GateIssue critical = issue(1, FindingType.VULNERABILITY, Severity.CRITICAL, null);
            GateIssue kev = new GateIssue(2, true, FindingType.VULNERABILITY, Severity.LOW, "CVE-2", "pkg", null, true, null);

            assertThat(PolicyGate.evaluate(List.of(critical), kevOnly).passed()).isTrue();
            assertThat(PolicyGate.evaluate(List.of(kev), kevOnly).passed()).isFalse();
        }
    }

    @Nested
    @DisplayName("hardening a requested policy")
    class Harden {

        @Test
        @DisplayName("a request that says nothing changes nothing and complains about nothing")
        void emptyRequestIsSilent() {
            PolicyGate.Hardened hardened = PolicyGate.harden(GatePolicy.BUILT_IN, RequestedPolicy.none());

            assertThat(hardened.policy()).isEqualTo(GatePolicy.BUILT_IN);
            assertThat(hardened.ignoredRelaxations()).isEmpty();
        }

        @Test
        @DisplayName("a lower threshold is accepted, because it fails on more")
        void loweringTheThresholdTightens() {
            PolicyGate.Hardened hardened = PolicyGate.harden(
                    GatePolicy.BUILT_IN,
                    RequestedPolicy.none().with(new SeverityRequest.Threshold(Severity.LOW)));

            assertThat(hardened.policy().failOnSeverity()).isEqualTo(Severity.LOW);
            assertThat(hardened.ignoredRelaxations()).isEmpty();
        }

        @Test
        @DisplayName("a higher threshold is refused, and the caller is told")
        void raisingTheThresholdIsRefused() {
            // The control this whole function exists for. Inverting the comparison would hand
            // every pipeline the power to raise its own threshold to critical and go green.
            PolicyGate.Hardened hardened = PolicyGate.harden(
                    GatePolicy.BUILT_IN,
                    RequestedPolicy.none().with(new SeverityRequest.Threshold(Severity.CRITICAL)));

            assertThat(hardened.policy().failOnSeverity()).isEqualTo(Severity.HIGH);
            assertThat(hardened.ignoredRelaxations()).containsExactly("fail_on_severity");
        }

        @Test
        @DisplayName("switching the severity rule off is refused")
        void disablingIsRefused() {
            PolicyGate.Hardened hardened =
                    PolicyGate.harden(GatePolicy.BUILT_IN, RequestedPolicy.none().with(new SeverityRequest.Disabled()));

            assertThat(hardened.policy().failOnSeverity()).isEqualTo(Severity.HIGH);
            assertThat(hardened.ignoredRelaxations()).containsExactly("fail_on_severity");
        }

        @Test
        @DisplayName("switching off a rule that was already off is not a relaxation")
        void disablingWhatIsAlreadyOffIsSilent() {
            GatePolicy noSeverityRule = new GatePolicy(null, true, false, false, false);

            PolicyGate.Hardened hardened =
                    PolicyGate.harden(noSeverityRule, RequestedPolicy.none().with(new SeverityRequest.Disabled()));

            assertThat(hardened.ignoredRelaxations()).isEmpty();
        }

        @Test
        @DisplayName("adding a threshold where there was none is a tightening")
        void addingAThresholdTightens() {
            GatePolicy noSeverityRule = new GatePolicy(null, true, false, false, false);

            PolicyGate.Hardened hardened = PolicyGate.harden(
                    noSeverityRule, RequestedPolicy.none().with(new SeverityRequest.Threshold(Severity.CRITICAL)));

            assertThat(hardened.policy().failOnSeverity()).isEqualTo(Severity.CRITICAL);
            assertThat(hardened.ignoredRelaxations()).isEmpty();
        }

        @Test
        @DisplayName("turning fixable-only on is a relaxation, because it evaluates fewer issues")
        void fixableOnlyIsRelaxedByBeingTrue() {
            // The flag whose strict value is `false`. Reading "stricter means true" off the
            // other three would let a pipeline shrink its own evaluated set.
            PolicyGate.Hardened hardened =
                    PolicyGate.harden(GatePolicy.BUILT_IN, RequestedPolicy.none().with(PolicyFlag.FIXABLE_ONLY, true));

            assertThat(hardened.policy().fixableOnly()).isFalse();
            assertThat(hardened.ignoredRelaxations()).containsExactly("fixable_only");
        }

        @Test
        @DisplayName("turning KEV off is refused; asking for triage to count is granted")
        void flagsTightenOneWayOnly() {
            PolicyGate.Hardened hardened = PolicyGate.harden(
                    GatePolicy.BUILT_IN,
                    RequestedPolicy.none()
                            .with(PolicyFlag.FAIL_ON_KEV, false)
                            .with(PolicyFlag.INCLUDE_TRIAGED, true));

            assertThat(hardened.policy().failOnKev()).isTrue();
            assertThat(hardened.policy().includeTriaged()).isTrue();
            assertThat(hardened.ignoredRelaxations()).containsExactly("fail_on_kev");
        }
    }
}
