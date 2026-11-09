package com.asmolabs.vectispire.common.domain.licenses;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("a licence policy as constructed")
class LicensePolicyTest {

    @Test
    @DisplayName("missing sets are empty, and null or blank entries are dropped")
    void nullsAreDropped() {
        LicensePolicy policy = new LicensePolicy(
                new HashSet<>(Arrays.asList(LicenseRiskCategory.FORBIDDEN, null)),
                new HashSet<>(Arrays.asList(" mit ", null, "  ")),
                null);

        assertThat(policy.disallowedCategories()).containsExactly(LicenseRiskCategory.FORBIDDEN);
        assertThat(policy.explicitlyAllowedLicenses()).containsExactly("MIT");
        assertThat(policy.explicitlyDisallowedLicenses()).isEmpty();
    }

    @Test
    @DisplayName("an exemption typed in lower case matches, whatever the default locale")
    void anExemptionMatchesCaseAside() {
        Locale previous = Locale.getDefault();
        try {
            // Turkish upper-cases "i" to a dotted capital, which is how a locale-sensitive
            // comparison stops matching "mit".
            Locale.setDefault(Locale.forLanguageTag("tr-TR"));
            LicensePolicy policy = new LicensePolicy(
                    java.util.Set.of(LicenseRiskCategory.FORBIDDEN), java.util.Set.of("mit"), java.util.Set.of("gpl-3.0"));

            assertThat(policy.isCompliant("MIT", LicenseRiskCategory.FORBIDDEN)).isTrue();
            assertThat(policy.isCompliant("mit", LicenseRiskCategory.FORBIDDEN)).isTrue();
            assertThat(policy.isCompliant("GPL-3.0", LicenseRiskCategory.PERMISSIVE)).isFalse();
        } finally {
            Locale.setDefault(previous);
        }
    }
}
