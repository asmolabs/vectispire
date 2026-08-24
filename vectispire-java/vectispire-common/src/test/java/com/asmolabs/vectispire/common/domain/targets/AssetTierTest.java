package com.asmolabs.vectispire.common.domain.targets;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.issues.Severity;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("AssetTier criticality and contextual SLA calculations")
class AssetTierTest {

    @Test
    @DisplayName("calculates strict 3-day SLA for Tier 1 Critical issues")
    void tier1CriticalSla() {
        AssetTier tier1 = AssetTier.TIER_1_MISSION_CRITICAL;
        assertThat(tier1.slaDuration(Severity.CRITICAL)).isEqualTo(Duration.ofDays(3));

        Instant seen = Instant.parse("2026-08-01T00:00:00Z");
        Instant withinSla = Instant.parse("2026-08-03T12:00:00Z");
        Instant breached = Instant.parse("2026-08-04T00:00:01Z");

        assertThat(tier1.isBreached(Severity.CRITICAL, seen, withinSla)).isFalse();
        assertThat(tier1.isBreached(Severity.CRITICAL, seen, breached)).isTrue();
    }

    @Test
    @DisplayName("calculates standard 14-day SLA for Tier 2 Critical issues")
    void tier2CriticalSla() {
        AssetTier tier2 = AssetTier.TIER_2_BUSINESS_OPERATIONAL;
        assertThat(tier2.slaDuration(Severity.CRITICAL)).isEqualTo(Duration.ofDays(14));
        assertThat(tier2.slaDuration(Severity.HIGH)).isEqualTo(Duration.ofDays(30));
    }

    @Test
    @DisplayName("defaults safely to TIER_2 when parsing unknown strings")
    void fallbackParsing() {
        assertThat(AssetTier.fromString(null)).isEqualTo(AssetTier.TIER_2_BUSINESS_OPERATIONAL);
        assertThat(AssetTier.fromString("")).isEqualTo(AssetTier.TIER_2_BUSINESS_OPERATIONAL);
        assertThat(AssetTier.fromString("INVALID")).isEqualTo(AssetTier.TIER_2_BUSINESS_OPERATIONAL);
        assertThat(AssetTier.fromString("tier_1_mission_critical")).isEqualTo(AssetTier.TIER_1_MISSION_CRITICAL);
    }
}
