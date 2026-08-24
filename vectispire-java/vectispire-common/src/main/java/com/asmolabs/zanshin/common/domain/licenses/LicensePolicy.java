package com.asmolabs.zanshin.common.domain.licenses;

import java.util.Set;

/**
 * Policy governing allowed open source license categories and specific exemptions.
 */
public record LicensePolicy(
        Set<LicenseRiskCategory> disallowedCategories,
        Set<String> explicitlyAllowedLicenses,
        Set<String> explicitlyDisallowedLicenses) {

    public static LicensePolicy defaultPolicy() {
        return new LicensePolicy(
                Set.of(LicenseRiskCategory.STRONG_COPYLEFT, LicenseRiskCategory.FORBIDDEN),
                Set.of(),
                Set.of());
    }

    public boolean isCompliant(String license, LicenseRiskCategory category) {
        if (license != null && explicitlyDisallowedLicenses.contains(license.toUpperCase())) {
            return false;
        }
        if (license != null && explicitlyAllowedLicenses.contains(license.toUpperCase())) {
            return true;
        }
        return !disallowedCategories.contains(category);
    }
}
