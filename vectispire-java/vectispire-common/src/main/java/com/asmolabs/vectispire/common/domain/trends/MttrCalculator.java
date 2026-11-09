package com.asmolabs.vectispire.common.domain.trends;

import com.asmolabs.vectispire.common.domain.issues.Severity;
import java.time.Duration;
import java.time.Instant;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.OptionalDouble;

/**
 * Pure calculation of Mean Time to Remediate (MTTR) across resolved issues.
 */
public final class MttrCalculator {

    private MttrCalculator() {}

    public record ResolvedIssue(Severity severity, Instant firstSeenAt, Instant resolvedAt) {}

    public record MttrResult(
            Map<Severity, Double> mttrBySeverityDays,
            Double overallMttrDays,
            int resolvedCount) {}

    public static MttrResult calculate(List<ResolvedIssue> resolvedIssues) {
        if (resolvedIssues == null || resolvedIssues.isEmpty()) {
            return new MttrResult(Map.of(), null, 0);
        }

        Map<Severity, List<Long>> daysBySeverity = new EnumMap<>(Severity.class);
        long totalDays = 0;
        int validCount = 0;

        for (ResolvedIssue issue : resolvedIssues) {
            if (issue.firstSeenAt() != null && issue.resolvedAt() != null && !issue.resolvedAt().isBefore(issue.firstSeenAt())) {
                long hours = Duration.between(issue.firstSeenAt(), issue.resolvedAt()).toHours();
                long days = Math.max(1, hours / 24);
                totalDays += days;
                validCount++;

                if (issue.severity() != null) {
                    daysBySeverity.computeIfAbsent(issue.severity(), k -> new java.util.ArrayList<>()).add(days);
                }
            }
        }

        if (validCount == 0) {
            return new MttrResult(Map.of(), null, 0);
        }

        Map<Severity, Double> resultBySeverity = new EnumMap<>(Severity.class);
        daysBySeverity.forEach((severity, list) -> {
            OptionalDouble avg = list.stream().mapToLong(Long::longValue).average();
            if (avg.isPresent()) {
                resultBySeverity.put(severity, Math.round(avg.getAsDouble() * 10.0) / 10.0);
            }
        });

        double overall = Math.round(((double) totalDays / validCount) * 10.0) / 10.0;
        return new MttrResult(Map.copyOf(resultBySeverity), overall, validCount);
    }
}
