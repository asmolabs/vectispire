package com.asmolabs.zanshin.common.domain.licenses;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

@DisplayName("LicenseRiskCategory SPDX classifier")
class LicenseRiskCategoryTest {

    @ParameterizedTest
    @CsvSource({
            "MIT, PERMISSIVE",
            "Apache-2.0, PERMISSIVE",
            "BSD-3-Clause, PERMISSIVE",
            "ISC, PERMISSIVE",
            "LGPL-2.1, WEAK_COPYLEFT",
            "LGPL-3.0-or-later, WEAK_COPYLEFT",
            "MPL-2.0, WEAK_COPYLEFT",
            "EPL-2.0, WEAK_COPYLEFT",
            "GPL-2.0, STRONG_COPYLEFT",
            "GPL-3.0-only, STRONG_COPYLEFT",
            "AGPL-3.0, STRONG_COPYLEFT",
            "SSPL-1.0, STRONG_COPYLEFT",
            "Commercial, FORBIDDEN",
            "Proprietary, FORBIDDEN"
    })
    void classifiesLicensesCorrectly(String spdx, LicenseRiskCategory expectedCategory) {
        assertThat(LicenseRiskCategory.classify(spdx)).isEqualTo(expectedCategory);
    }

    @Test
    @DisplayName("evaluates compliance according to license policy")
    void evaluatesPolicyCompliance() {
        LicensePolicy policy = LicensePolicy.defaultPolicy();

        assertThat(policy.isCompliant("MIT", LicenseRiskCategory.PERMISSIVE)).isTrue();
        assertThat(policy.isCompliant("LGPL-2.1", LicenseRiskCategory.WEAK_COPYLEFT)).isTrue();
        assertThat(policy.isCompliant("GPL-3.0", LicenseRiskCategory.STRONG_COPYLEFT)).isFalse();
        assertThat(policy.isCompliant("AGPL-3.0", LicenseRiskCategory.STRONG_COPYLEFT)).isFalse();
    }
}
