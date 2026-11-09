package com.asmolabs.vectispire.common.domain.targets;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("AssetTier parsing")
class AssetTierTest {

    @Test
    @DisplayName("defaults safely to TIER_2 when parsing unknown strings")
    void fallbackParsing() {
        assertThat(AssetTier.fromString(null)).isEqualTo(AssetTier.TIER_2_BUSINESS_OPERATIONAL);
        assertThat(AssetTier.fromString("")).isEqualTo(AssetTier.TIER_2_BUSINESS_OPERATIONAL);
        assertThat(AssetTier.fromString("INVALID")).isEqualTo(AssetTier.TIER_2_BUSINESS_OPERATIONAL);
        assertThat(AssetTier.fromString("tier_1_mission_critical")).isEqualTo(AssetTier.TIER_1_MISSION_CRITICAL);
    }

    @Test
    @DisplayName("refuses an unknown tier on input, where the lenient read would store tier 2 in silence")
    void inputIsStrict() {
        assertThat(AssetTier.fromInput(null)).isEqualTo(AssetTier.TIER_2_BUSINESS_OPERATIONAL);
        assertThat(AssetTier.fromInput(" ")).isEqualTo(AssetTier.TIER_2_BUSINESS_OPERATIONAL);
        assertThat(AssetTier.fromInput("tier_3_internal")).isEqualTo(AssetTier.TIER_3_INTERNAL);
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> AssetTier.fromInput("TIER_1"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("TIER_1_MISSION_CRITICAL");
    }
}
