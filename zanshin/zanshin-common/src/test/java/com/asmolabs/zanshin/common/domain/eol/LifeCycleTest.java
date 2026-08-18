package com.asmolabs.zanshin.common.domain.eol;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.zanshin.common.domain.issues.Severity;
import java.time.Duration;
import java.time.LocalDate;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

@DisplayName("end of life")
class LifeCycleTest {

    private static final LocalDate TODAY = LocalDate.of(2026, 8, 13);

    private static LifeCycle.Release release(String name, String eolFrom, Boolean eol, Boolean maintained) {
        return new LifeCycle.Release(name, eolFrom == null ? null : LocalDate.parse(eolFrom), eol, maintained, null);
    }

    @Nested
    @DisplayName("matching a version to a cycle")
    class Matching {

        @Test
        @DisplayName("compares component by component, not by string prefix")
        void neverMatchesByPrefix() {
            // "3.14" starts with "3.1", so a prefix test files Python 3.14 under the 3.1 cycle
            // and announces a support window that closed years ago.
            LifeCycle.Product python = new LifeCycle.Product(
                    "python", List.of(release("3.1", "2012-04-09", true, false), release("3.14", "2030-10-01", false, true)));

            assertThat(LifeCycle.matchRelease(python, "3.14.0")).hasValueSatisfying(
                    r -> assertThat(r.name()).isEqualTo("3.14"));
        }

        @Test
        @DisplayName("the longest matching cycle wins")
        void longestCycleWins() {
            LifeCycle.Product product = new LifeCycle.Product(
                    "thing", List.of(release("8", "2027-01-01", false, true), release("8.1", "2029-01-01", false, true)));

            assertThat(LifeCycle.matchRelease(product, "8.1.3")).hasValueSatisfying(
                    r -> assertThat(r.name()).isEqualTo("8.1"));
        }

        @ParameterizedTest(name = "reads {0} as the cycle {1}")
        @CsvSource({"'9.7 (Plow)', 9.7", "3.12.1-rc1, 3.12", "22.04, 22.04"})
        void toleratesDecoratedVersions(String version, String cycle) {
            // Neither a distribution's decorated version nor a package's build suffix must stop
            // the cycle from being recognized.
            LifeCycle.Product product = new LifeCycle.Product("p", List.of(release(cycle, null, false, true)));

            assertThat(LifeCycle.matchRelease(product, version)).isPresent();
        }

        @Test
        @DisplayName("matches nothing rather than the nearest thing")
        void matchesNothingWhenNoCycleFits() {
            LifeCycle.Product product = new LifeCycle.Product("p", List.of(release("9", null, false, true)));

            assertThat(LifeCycle.matchRelease(product, "10.2")).isEmpty();
        }
    }

    @Nested
    @DisplayName("the verdict")
    class Assessment {

        @Test
        @DisplayName("a cycle already past its end is high, not medium")
        void pastEndIsHigh() {
            // Not because something is broken today, but because nothing will be fixed
            // tomorrow — which is not a "medium" for a component you ship.
            assertThat(LifeCycle.assess(release("8", "2024-01-01", false, false), TODAY, LifeCycle.DEFAULT_WARNING_WINDOW))
                    .hasValueSatisfying(v -> assertThat(v.severity()).isEqualTo(Severity.HIGH));
        }

        @Test
        @DisplayName("a deadline inside the window is medium")
        void upcomingEndIsMedium() {
            assertThat(LifeCycle.assess(release("9", "2026-10-01", false, true), TODAY, LifeCycle.DEFAULT_WARNING_WINDOW))
                    .hasValueSatisfying(v -> assertThat(v.severity()).isEqualTo(Severity.MEDIUM));
        }

        @Test
        @DisplayName("a deadline beyond the window is not reported at all")
        void distantEndIsSilent() {
            // Everything reaches end of life one day. Flagging a version supported for another
            // three years teaches people to filter this finding type out entirely.
            assertThat(LifeCycle.assess(release("10", "2030-01-01", false, true), TODAY, LifeCycle.DEFAULT_WARNING_WINDOW))
                    .isEmpty();
        }

        @Test
        @DisplayName("an abandoned product with no date is high")
        void abandonedWithoutADateIsHigh() {
            // There is no deadline to warn about because the deadline has no date, which is
            // worse than a dated one, not milder.
            assertThat(LifeCycle.assess(release("1", null, null, false), TODAY, LifeCycle.DEFAULT_WARNING_WINDOW))
                    .hasValueSatisfying(v -> {
                        assertThat(v.severity()).isEqualTo(Severity.HIGH);
                        assertThat(v.eolDate()).isNull();
                    });
        }

        @Test
        @DisplayName("the catalog's own eol flag is enough, with or without a date")
        void trustsTheCatalogFlag() {
            assertThat(LifeCycle.assess(release("7", null, true, false), TODAY, LifeCycle.DEFAULT_WARNING_WINDOW))
                    .hasValueSatisfying(v -> assertThat(v.severity()).isEqualTo(Severity.HIGH));
        }

        @Test
        @DisplayName("a maintained cycle with no end date says nothing")
        void maintainedIsSilent() {
            assertThat(LifeCycle.assess(release("11", null, false, true), TODAY, LifeCycle.DEFAULT_WARNING_WINDOW))
                    .isEmpty();
        }

        @Test
        @DisplayName("the window is configurable, and widening it reports more")
        void windowIsConfigurable() {
            LifeCycle.Release release = release("10", "2027-06-01", false, true);

            assertThat(LifeCycle.assess(release, TODAY, Duration.ofDays(180))).isEmpty();
            assertThat(LifeCycle.assess(release, TODAY, Duration.ofDays(365))).isPresent();
        }
    }

    @Nested
    @DisplayName("what to do about it")
    class Recommendation {

        @Test
        @DisplayName("recommends the most recent maintained release")
        void recommendsMaintained() {
            LifeCycle.Product product = new LifeCycle.Product("p", List.of(
                    new LifeCycle.Release("12", null, false, true, "12.4"),
                    new LifeCycle.Release("11", null, true, false, "11.9")));

            assertThat(LifeCycle.recommendedVersion(product)).contains("12.4");
        }

        @Test
        @DisplayName("says nothing when nothing is maintained")
        void nothingToRecommend() {
            LifeCycle.Product product = new LifeCycle.Product("p", List.of(release("1", null, true, false)));

            assertThat(LifeCycle.recommendedVersion(product)).isEmpty();
        }
    }

    @Nested
    @DisplayName("purl normalization")
    class Purl {

        @ParameterizedTest(name = "{0} names the product {1}")
        @CsvSource({
            "pkg:rpm/redhat/openssl@3.5.1?arch=x86_64, pkg:rpm/redhat/openssl",
            "pkg:npm/lodash@4.17.21, pkg:npm/lodash",
            "PKG:NPM/Lodash, pkg:npm/lodash",
            "pkg:deb/debian/bash@5.2#subpath, pkg:deb/debian/bash"
        })
        void stripsVersionAndQualifiers(String purl, String expected) {
            // A SBOM purl carries both where the catalog's identifiers carry neither. Comparing
            // them as they are matches nothing, and matching nothing looks exactly like "this
            // product has no known end of life".
            assertThat(Purls.normalize(purl)).isEqualTo(expected);
        }
    }
}
