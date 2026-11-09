package com.asmolabs.vectispire.common.domain.targets;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;

/**
 * Business criticality classification of monitored targets (repositories & containers).
 *
 * <p><b>It sets no remediation deadline.</b> It used to carry a table of SLA days per severity and a
 * breach test that nothing in production called, beside {@code RemediationSla}, whose windows are
 * the ones the issues, the reports and the SIEM signal read. Two rules for one deadline drift apart
 * in silence; the unused one was removed rather than kept as a second answer.
 */
public enum AssetTier {
    TIER_1_MISSION_CRITICAL("Tier 1 - Mission Critical"),
    TIER_2_BUSINESS_OPERATIONAL("Tier 2 - Business Operational"),
    TIER_3_INTERNAL("Tier 3 - Internal / Lab");

    private final String displayName;

    AssetTier(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String wireName() {
        return name();
    }

    /**
     * A stored tier, read leniently: anything unreadable is the default.
     *
     * <p>For <em>reading</em> a row only. A tier written by an older version, or by hand, must not
     * take the inventory down; the default is the documented behaviour of a target nobody tiered.
     */
    public static AssetTier fromString(String value) {
        if (value == null || value.isBlank()) {
            return TIER_2_BUSINESS_OPERATIONAL;
        }
        return byName(value).orElse(TIER_2_BUSINESS_OPERATIONAL);
    }

    /**
     * A tier an operator submitted: blank is the default, anything else must name one.
     *
     * <p><b>Refused rather than read leniently</b>, unlike {@link #fromString}. A misspelt
     * {@code TIER_1} used to become {@code TIER_2} in silence — a mission-critical target stored
     * with a deadline four times longer than the one the operator chose, and a screen that showed
     * "Tier 2" as if that had been the choice.
     *
     * @throws InvalidInputException for a value that names no tier
     */
    public static AssetTier fromInput(String value) {
        if (value == null || value.isBlank()) {
            return TIER_2_BUSINESS_OPERATIONAL;
        }
        return byName(value).orElseThrow(() -> new InvalidInputException(
                "Unknown asset tier \"" + value.trim() + "\". Expected one of: "
                        + String.join(", ", Arrays.stream(values()).map(Enum::name).toList()) + "."));
    }

    private static Optional<AssetTier> byName(String value) {
        String normalized = value.trim().toUpperCase(Locale.ROOT);
        return Arrays.stream(values()).filter(t -> t.name().equals(normalized)).findFirst();
    }
}
