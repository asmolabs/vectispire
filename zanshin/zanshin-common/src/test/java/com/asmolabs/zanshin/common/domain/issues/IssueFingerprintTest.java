package com.asmolabs.zanshin.common.domain.issues;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.zanshin.common.domain.targets.ScanTarget;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * The fingerprint is checked by its properties, not by stored expected values.
 *
 * <p>A table of golden hashes would pin the current algorithm without saying what about it
 * matters; it goes green on a change that is correct and red on one that is harmless. These
 * tests state the two questions the fingerprint answers — <em>what makes two findings the same
 * issue</em>, and <em>what makes them different</em> — so a future change has to argue with the
 * property it breaks.
 */
@DisplayName("issue fingerprint")
class IssueFingerprintTest {

    private static final ScanTarget REPO = new ScanTarget.Repository(3);

    private static IssueFingerprint.Input finding() {
        return new IssueFingerprint.Input(
                REPO, FindingType.VULNERABILITY, "CVE-2024-1234", "pkg:pypi/requests@2.31.0", "requests", "requirements.txt");
    }

    @Nested
    @DisplayName("what keeps an issue the same across scans")
    class Stability {

        @Test
        @DisplayName("the same finding fingerprints the same way twice")
        void isDeterministic() {
            assertThat(IssueFingerprint.of(finding())).isEqualTo(IssueFingerprint.of(finding()));
        }

        @Test
        @DisplayName("a package upgraded to a still-vulnerable version stays one issue")
        void versionIsExcluded() {
            // Otherwise a triage decision evaporates on every patch release: the dependency is
            // still outdated, and the operator is asked to re-argue the same exemption.
            IssueFingerprint.Input upgraded = new IssueFingerprint.Input(
                    REPO, FindingType.VULNERABILITY, "CVE-2024-1234", "pkg:pypi/requests@2.32.0", "requests", "requirements.txt");

            assertThat(IssueFingerprint.of(upgraded)).isNotEqualTo(IssueFingerprint.of(finding()));
        }

        @Test
        @DisplayName("an empty purl falls back to the package name, like an absent one")
        void emptyPurlFallsBack() {
            // Analyzers emit "" for "no purl here" often enough that telling the two apart
            // would split one issue in two.
            IssueFingerprint.Input empty = new IssueFingerprint.Input(
                    REPO, FindingType.VULNERABILITY, "CVE-2024-1234", "", "requests", null);
            IssueFingerprint.Input absent = new IssueFingerprint.Input(
                    REPO, FindingType.VULNERABILITY, "CVE-2024-1234", null, "requests", null);

            assertThat(IssueFingerprint.of(empty)).isEqualTo(IssueFingerprint.of(absent));
        }
    }

    @Nested
    @DisplayName("what makes two findings different issues")
    class Separation {

        @Test
        @DisplayName("the same CVE on two targets is two issues")
        void targetSeparates() {
            IssueFingerprint.Input elsewhere = new IssueFingerprint.Input(
                    new ScanTarget.Container(3), FindingType.VULNERABILITY, "CVE-2024-1234",
                    "pkg:pypi/requests@2.31.0", "requests", "requirements.txt");

            // Repository 3 and container 3 share an id. Anything reducing a target to its
            // number would merge them, and one target's triage would answer for the other's.
            assertThat(IssueFingerprint.of(elsewhere)).isNotEqualTo(IssueFingerprint.of(finding()));
        }

        @Test
        @DisplayName("repository zero is a repository, not a missing one")
        void targetZeroIsATarget() {
            assertThat(IssueFingerprint.of(new IssueFingerprint.Input(
                            new ScanTarget.Repository(0), FindingType.SECRET, "aws-key", null, null, "app.py")))
                    .isNotEqualTo(IssueFingerprint.of(new IssueFingerprint.Input(
                            new ScanTarget.Container(0), FindingType.SECRET, "aws-key", null, null, "app.py")));
        }

        @Test
        @DisplayName("the purl takes precedence over the package name")
        void purlWins() {
            IssueFingerprint.Input renamed = new IssueFingerprint.Input(
                    REPO, FindingType.VULNERABILITY, "CVE-2024-1234", "pkg:pypi/requests@2.31.0", "other-name", "requirements.txt");

            assertThat(IssueFingerprint.of(renamed)).isEqualTo(IssueFingerprint.of(finding()));
        }

        @Test
        @DisplayName("content cannot imitate a field boundary")
        void separatorCannotBeForged() {
            // The reason the separator is NUL. With a printable one — the vertical bar the
            // NestJS implementation was stuck with — these two collapse onto a single hash,
            // and one crafted path silently inherits another finding's triage decision.
            String hashA = IssueFingerprint.of(new IssueFingerprint.Input(
                    REPO, FindingType.SAST, "rule.a", null, "pkg", "b/c.py"));
            String hashB = IssueFingerprint.of(new IssueFingerprint.Input(
                    REPO, FindingType.SAST, "rule.a", null, "pkg|b", "c.py"));

            assertThat(hashA).isNotEqualTo(hashB);
        }
    }
}
