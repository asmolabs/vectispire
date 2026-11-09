package com.asmolabs.vectispire.common.domain.trends;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.issues.Severity;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("MttrCalculator MTTR computation")
class MttrCalculatorTest {

    @Test
    @DisplayName("calculates average MTTR by severity and overall")
    void calculatesMttr() {
        Instant now = Instant.parse("2026-08-22T10:00:00Z");

        List<MttrCalculator.ResolvedIssue> resolved = List.of(
                new MttrCalculator.ResolvedIssue(Severity.CRITICAL, now.minus(5, ChronoUnit.DAYS), now),
                new MttrCalculator.ResolvedIssue(Severity.CRITICAL, now.minus(7, ChronoUnit.DAYS), now),
                new MttrCalculator.ResolvedIssue(Severity.HIGH, now.minus(12, ChronoUnit.DAYS), now),
                new MttrCalculator.ResolvedIssue(Severity.HIGH, now.minus(20, ChronoUnit.DAYS), now));

        MttrCalculator.MttrResult result = MttrCalculator.calculate(resolved);

        assertThat(result.resolvedCount()).isEqualTo(4);
        assertThat(result.mttrBySeverityDays().get(Severity.CRITICAL)).isEqualTo(6.0);
        assertThat(result.mttrBySeverityDays().get(Severity.HIGH)).isEqualTo(16.0);
        assertThat(result.overallMttrDays()).isEqualTo(11.0);
    }

    @Test
    @DisplayName("handles empty input gracefully")
    void handlesEmpty() {
        MttrCalculator.MttrResult result = MttrCalculator.calculate(List.of());
        assertThat(result.resolvedCount()).isEqualTo(0);
        assertThat(result.overallMttrDays()).isNull();
        assertThat(result.mttrBySeverityDays()).isEmpty();
    }
}
