package com.asmolabs.vectispire.common.domain.dependencies;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("a Maven version range")
class MavenVersionRangeTest {

    @Test
    @DisplayName("includes a bound in square brackets and excludes one in parentheses")
    void bounds() {
        MavenVersionRange range = MavenVersionRange.parse("[1.17,2.0)");
        assertThat(range.contains("1.17")).isTrue();
        assertThat(range.contains("1.17.0")).as("Maven's equality, not the string's").isTrue();
        assertThat(range.contains("1.17.7")).isTrue();
        assertThat(range.contains("1.99.99")).isTrue();
        assertThat(range.contains("2.0")).isFalse();
        assertThat(range.contains("2.0.0")).isFalse();
        assertThat(range.contains("1.16.9")).isFalse();
        assertThat(range.contains("1.9")).as("1.9 is below 1.17, whatever a string sort says").isFalse();

        MavenVersionRange inclusive = MavenVersionRange.parse("(1.17,2.0]");
        assertThat(inclusive.contains("1.17")).isFalse();
        assertThat(inclusive.contains("1.17.1")).isTrue();
        assertThat(inclusive.contains("2.0")).isTrue();
        assertThat(inclusive.contains("2.0.1")).isFalse();
    }

    @Test
    @DisplayName("reads an unbounded side, one exact version, and a union of ranges")
    void shapes() {
        MavenVersionRange below = MavenVersionRange.parse("(,2.0)");
        assertThat(below.contains("0.1")).isTrue();
        assertThat(below.contains("2.0")).isFalse();
        MavenVersionRange above = MavenVersionRange.parse("[1.5,)");
        assertThat(above.contains("1.5")).isTrue();
        assertThat(above.contains("99")).isTrue();
        assertThat(above.contains("1.4.9")).isFalse();

        MavenVersionRange exact = MavenVersionRange.parse("[1.17.7]");
        assertThat(exact.contains("1.17.7")).isTrue();
        assertThat(exact.contains("1.17.7.0")).isTrue();
        assertThat(exact.contains("1.17.8")).isFalse();
        assertThat(exact.contains("1.17.6")).isFalse();

        MavenVersionRange union = MavenVersionRange.parse("[1.0,1.2], [1.5,)");
        assertThat(union.contains("1.1")).isTrue();
        assertThat(union.contains("1.2")).isTrue();
        assertThat(union.contains("1.3")).isFalse();
        assertThat(union.contains("1.5")).isTrue();
        assertThat(union.contains("3")).isTrue();
    }

    @Test
    @DisplayName("applies Maven's qualifiers: a snapshot or a candidate of the upper bound is below it, a .RELEASE is it")
    void qualifiers() {
        MavenVersionRange range = MavenVersionRange.parse("[1.17,2.0)");
        assertThat(range.contains("2.0-SNAPSHOT")).as("a snapshot of 2.0 comes before 2.0").isTrue();
        assertThat(range.contains("2.0-RC1")).isTrue();
        assertThat(range.contains("1.17-SNAPSHOT")).as("and before 1.17, out of [1.17").isFalse();
        assertThat(range.contains("1.17.0.RELEASE")).isTrue();
        assertThat(MavenVersionRange.parse("[5.3.0]").contains("5.3.0.RELEASE")).isTrue();
        assertThat(MavenVersionRange.parse("(,5.3.0)").contains("5.3.0.RELEASE")).isFalse();
        assertThat(MavenVersionRange.parse("[1.0,1.1)").contains("1.0-sp1")).as("a service pack follows its release")
                .isTrue();
    }

    @Test
    @DisplayName("refuses in words what does not read, what Maven refuses, and what nobody means")
    void refusals() {
        refused("1.0", "opens with [ or (");
        refused("[1.0,2.0", "closes with ] or )");
        refused("(1.0)", "single version is written in square brackets");
        refused("[]", "names no version");
        refused("[2.0,1.0]", "lower bound 2.0 is above its upper bound 1.0");
        refused("(1.0,1.0)", "admits no version");
        refused("[1.0,1.0)", "admits no version");
        refused("[,2.0)", "unbounded side is written with a parenthesis");
        refused("[1.0,]", "unbounded side is written with a parenthesis");
        refused("(,)", "admits every version");
        refused("[1.0,2.0,3.0]", "is not a version");
        refused("[1.0,1.5],[1.2,2.0]", "overlap");
        refused("[1.0,1.5],[1.5,2.0]", "overlap");
        refused("[1.5,2.0],[1.0,1.2]", "overlap");
        refused("[1.0,1.2],(,3.0)", "overlap");
        refused("[1.0,1.2],", "followed by another range");
        refused("[1.0,1.2] 1.4", "follows the ranges");
        refused("[1 .0,2]", "is not a version");
        assertThat(MavenVersionRange.parse("[1.0,1.5),[1.5,2.0]").contains("1.5")).as("adjacent, not overlapping")
                .isTrue();
    }

    @Test
    @DisplayName("reads stored text without refusing it: a text that is no range is absent")
    void reading() {
        assertThat(MavenVersionRange.read("3.2.1")).isEmpty();
        assertThat(MavenVersionRange.read("[3.2")).isEmpty();
        assertThat(MavenVersionRange.read("[3.2,4)")).isPresent();
    }

    private static void refused(String spec, String words) {
        assertThatThrownBy(() -> MavenVersionRange.parse(spec)).as(spec).isInstanceOf(InvalidInputException.class)
                .hasMessageContaining(words);
    }
}
