package com.asmolabs.vectispire.common.domain.targets;

import com.asmolabs.vectispire.common.domain.issues.Severity;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;

/**
 * Business criticality classification of monitored targets (repositories & containers).
 *
 * <p>Drives contextual SLA deadlines, Security Gate severity thresholds, and notification urgency.
 */
public enum AssetTier {
    TIER_1_MISSION_CRITICAL("Tier 1 - Mission Critical", 3, 14, 30, 90),
    TIER_2_BUSINESS_OPERATIONAL("Tier 2 - Business Operational", 14, 30, 60, 180),
    TIER_3_INTERNAL("Tier 3 - Internal / Lab", 30, 60, 90, 365);

    private final String displayName;
    private final int criticalSlaDays;
    private final int highSlaDays;
    private final int mediumSlaDays;
    private final int lowSlaDays;

    AssetTier(String displayName, int criticalSlaDays, int highSlaDays, int mediumSlaDays, int lowSlaDays) {
        this.displayName = displayName;
        this.criticalSlaDays = criticalSlaDays;
        this.highSlaDays = highSlaDays;
        this.mediumSlaDays = mediumSlaDays;
        this.lowSlaDays = lowSlaDays;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String wireName() {
        return name();
    }

    public Duration slaDuration(Severity severity) {
        if (severity == null) {
            return Duration.ofDays(mediumSlaDays);
        }
        return switch (severity) {
            case CRITICAL -> Duration.ofDays(criticalSlaDays);
            case HIGH -> Duration.ofDays(highSlaDays);
            case MEDIUM -> Duration.ofDays(mediumSlaDays);
            case LOW, NEGLIGIBLE, UNKNOWN -> Duration.ofDays(lowSlaDays);
        };
    }

    public Instant deadline(Severity severity, Instant firstSeenAt) {
        return firstSeenAt.plus(slaDuration(severity));
    }

    public boolean isBreached(Severity severity, Instant firstSeenAt, Instant now) {
        return now.isAfter(deadline(severity, firstSeenAt));
    }

    public static AssetTier fromString(String value) {
        if (value == null || value.isBlank()) {
            return TIER_2_BUSINESS_OPERATIONAL;
        }
        String normalized = value.trim().toUpperCase(Locale.ROOT);
        return Arrays.stream(values())
                .filter(t -> t.name().equals(normalized))
                .findFirst()
                .orElse(TIER_2_BUSINESS_OPERATIONAL);
    }
}
