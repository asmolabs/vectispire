package com.asmolabs.vectispire.common.domain.dependencies;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("comparer des versions")
class VersionsTest {

    @Test
    @DisplayName("sorts 2.17.1 after 2.9.0, which a string sort gets backwards")
    void numbersAreNumbers() {
        // **The case that justifies the class.** Lexicographically "2.9.0" comes after "2.17.1",
        // and the remediation screen would then advise a version that leaves the hole open — wrong
        // advice is worse than no advice.
        assertThat(Versions.compare("2.17.1", "2.9.0")).isPositive();
        assertThat(Versions.compare("1.10", "1.9")).isPositive();
        assertThat(Versions.compare("1.0.0", "1.0.0")).isZero();
    }

    @Test
    @DisplayName("reads 2.17 and 2.17.0 as the same version")
    void missingSegmentsAreZero() {
        assertThat(Versions.compare("2.17", "2.17.0")).isZero();
        assertThat(Versions.compare("2.17.0.0", "2.17")).isZero();
        assertThat(Versions.compare("2.17.1", "2.17")).isPositive();
    }

    @Test
    @DisplayName("prefers a digit to a word, the safe way round")
    void digitsOutrankWords() {
        // Advising a version one notch too high is harmless; advising a pre-release in place of the
        // final version leaves the hole.
        assertThat(Versions.compare("2.0", "2.rc1")).isPositive();
        assertThat(Versions.compare("1.0.0", "1.0.0-alpha")).isPositive();
    }

    @Test
    @DisplayName("choisit la plus haute d'une liste, et ne choisit rien quand il n'y a rien")
    void highestOfMany() {
        assertThat(Versions.highest(List.of("2.12.2", "2.3.2", "2.17.1"))).contains("2.17.1");
        assertThat(Versions.highest(List.of("  2.17.1  ", ""))).contains("2.17.1");

        // **Empty, and not a placeholder text.** "No fixed version published" and "upgrade to this
        // one" are two different answers; the field used to carry the string "latest-patch", shown
        // behind an arrow on the dashboard.
        assertThat(Versions.highest(List.of())).isEmpty();
        assertThat(Versions.highest(List.of("", "   "))).isEmpty();
        assertThat(Versions.highest(null)).isEqualTo(Optional.empty());
    }

    @Test
    @DisplayName("splits the list the scanners report")
    void splitsWhatScannersReport() {
        // `fix_versions` is not a version but an enumeration: a maintenance branch fixed at the
        // same time as the main one puts both in it.
        assertThat(Versions.split("2.12.2, 2.3.2,2.17.1"))
                .containsExactly("2.12.2", "2.3.2", "2.17.1");
        assertThat(Versions.split(null)).isEmpty();
        assertThat(Versions.split("  ")).isEmpty();
    }

    @Test
    @DisplayName("does not throw on a segment larger than a long")
    void absurdSegmentsDoNotThrow() {
        // Packed build identifiers exceed a long's capacity; the comparison then falls back on
        // length and then text, and above all does not break the screen.
        assertThat(Versions.compare("1.99999999999999999999", "1.2")).isPositive();
        assertThat(Versions.highest(List.of("1.99999999999999999999", "1.2")))
                .contains("1.99999999999999999999");
    }
}
