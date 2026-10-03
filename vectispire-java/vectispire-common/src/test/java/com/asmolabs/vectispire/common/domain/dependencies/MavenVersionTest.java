package com.asmolabs.vectispire.common.domain.dependencies;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Maven's own orderings, so that a range bound in a checklist admits what Maven would. When written,
 * {@link MavenVersion} was compared outside the build with {@code maven-artifact} 3.9.6's {@code
 * ComparableVersion} — every pair of these lists and 200,000 random pairs of qualifier-laden strings,
 * no disagreement — and the lists below are the orderings that comparison confirmed.
 */
@DisplayName("a Maven version")
class MavenVersionTest {

    private static final List<String> QUALIFIERS = List.of("1-alpha2snapshot", "1-alpha2", "1-alpha-123", "1-beta-2",
            "1-beta123", "1-m2", "1-m11", "1-rc", "1-cr2", "1-rc123", "1-SNAPSHOT", "1", "1-sp", "1-sp2", "1-sp123",
            "1-abc", "1-def", "1-pom-1", "1-1-snapshot", "1-1", "1-2", "1-123");

    private static final List<String> NUMBERS = List.of("2.0", "2.0.a", "2-1", "2.0.2", "2.0.123", "2.1.0",
            "2.1-a", "2.1b", "2.1-c", "2.1-1", "2.1.0.1", "2.2", "2.123", "11.a2", "11.a11", "11.b2", "11.b11", "11.m2",
            "11.m11", "11", "11.a", "11b", "11c", "11m");

    @Test
    @DisplayName("orders qualifiers as Maven does: alpha, beta, milestone, rc, snapshot, release, sp, then unknown ones")
    void qualifiers() {
        assertAscending(QUALIFIERS);
    }

    @Test
    @DisplayName("orders numbers numerically, a qualifier before the number at its place")
    void numbers() {
        assertAscending(NUMBERS);
    }

    @Test
    @DisplayName("reads trailing zeros, release aliases and the one-letter shorthands as the same version")
    void equalities() {
        assertEqual("1", "1.0", "1.0.0", "1-0", "1.0-0", "1.ga", "1-ga", "1.final", "1-final", "1.release",
                "1-release", "1.0.0.RELEASE");
        assertEqual("1a1", "1-a1", "1-alpha-1", "1alpha1");
        assertEqual("2.0.a", "2.0.0.a", "2-a");
        assertEqual("1.0.0.M1", "1-m1", "1-milestone-1");
        assertEqual("1b2", "1-b2", "1-beta-2", "1beta2");
        assertEqual("1m3", "1-m3", "1-milestone-3", "1milestone3");
        assertEqual("1rc", "1cr", "1-rc", "1-cr", "1.RC");
        assertEqual("1-SNAPSHOT", "1-snapshot", "1.0-SNAPSHOT");
        assertEqual("12345678901234567890", "12345678901234567890.0");
    }

    @Test
    @DisplayName("puts a snapshot and a release candidate before their release, a service pack after")
    void releases() {
        assertAscending(List.of("1.17.0-alpha", "1.17.0-RC1", "1.17.0-SNAPSHOT", "1.17.0", "1.17.0.RELEASE-sp",
                "1.17.1", "1.17.10", "2.0-SNAPSHOT", "2.0"));
        assertThat(MavenVersion.of("5.3.0.RELEASE").compareTo(MavenVersion.of("5.3.0"))).isZero();
        assertThat(MavenVersion.of("1-0.1").compareTo(MavenVersion.of("1"))).as("a sub-list read past its zero")
                .isPositive();
        assertThat(MavenVersion.of("1-0-alpha").compareTo(MavenVersion.of("1"))).isNegative();
        assertThat(MavenVersion.of("1.9").compareTo(MavenVersion.of("1.10"))).as("not a string sort").isNegative();
    }

    private static void assertAscending(List<String> versions) {
        for (int low = 0; low < versions.size(); low++) {
            for (int high = low + 1; high < versions.size(); high++) {
                MavenVersion lower = MavenVersion.of(versions.get(low));
                MavenVersion higher = MavenVersion.of(versions.get(high));
                assertThat(lower.compareTo(higher)).as(versions.get(low) + " < " + versions.get(high)).isNegative();
                assertThat(higher.compareTo(lower)).as(versions.get(high) + " > " + versions.get(low)).isPositive();
            }
        }
    }

    private static void assertEqual(String... versions) {
        for (String left : versions) {
            for (String right : versions) {
                assertThat(MavenVersion.of(left).compareTo(MavenVersion.of(right))).as(left + " = " + right).isZero();
            }
        }
    }
}
