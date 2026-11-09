package com.asmolabs.vectispire.common.domain.scorecard;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

@DisplayName("SecurityGrade evaluation and thresholds")
class SecurityGradeTest {

    @ParameterizedTest
    @CsvSource({
            "100, A_PLUS",
            "95, A_PLUS",
            "90, A",
            "85, A",
            "75, B",
            "70, B",
            "60, C",
            "55, C",
            "45, D",
            "40, D",
            "30, F",
            "0, F"
    })
    void mapsScoreToGradeCorrectly(int score, SecurityGrade expectedGrade) {
        assertThat(SecurityGrade.fromScore(score)).isEqualTo(expectedGrade);
    }

    @Test
    @DisplayName("generates valid SVG badge markup")
    void generatesSvgBadge() {
        String svg = SvgBadgeGenerator.generateBadge("vectispire security", "A+", "#4c1");

        assertThat(svg).contains("<svg");
        assertThat(svg).contains("vectispire security");
        assertThat(svg).contains("A+");
        assertThat(svg).contains("#4c1");
        assertThat(svg).endsWith("</svg>");
    }
}
