package com.asmolabs.zanshin.common.domain.licenses;

import java.util.Locale;
import java.util.Set;

/**
 * Categorization of open source software licenses according to copyleft & legal risk.
 */
public enum LicenseRiskCategory {
    PERMISSIVE,
    WEAK_COPYLEFT,
    STRONG_COPYLEFT,
    FORBIDDEN,
    UNKNOWN;

    private static final Set<String> PERMISSIVE_LICENSES = Set.of(
            "MIT", "APACHE-2.0", "APACHE-1.1", "BSD-2-CLAUSE", "BSD-3-CLAUSE", "BSD-4-CLAUSE",
            "ISC", "CC0-1.0", "UNLICENSE", "0BSD", "ZLIB", "POSTGRESQL", "WTFPL", "JSON");

    private static final Set<String> WEAK_COPYLEFT_LICENSES = Set.of(
            "LGPL-2.0-ONLY", "LGPL-2.0-OR-LATER", "LGPL-2.1-ONLY", "LGPL-2.1-OR-LATER", "LGPL-3.0-ONLY", "LGPL-3.0-OR-LATER",
            "LGPL-2.0", "LGPL-2.1", "LGPL-3.0", "MPL-1.1", "MPL-2.0", "CDDL-1.0", "CDDL-1.1", "EPL-1.0", "EPL-2.0");

    private static final Set<String> STRONG_COPYLEFT_LICENSES = Set.of(
            "GPL-1.0-ONLY", "GPL-1.0-OR-LATER", "GPL-2.0-ONLY", "GPL-2.0-OR-LATER", "GPL-3.0-ONLY", "GPL-3.0-OR-LATER",
            "GPL-1.0", "GPL-2.0", "GPL-3.0", "AGPL-1.0", "AGPL-3.0", "AGPL-3.0-ONLY", "AGPL-3.0-OR-LATER",
            "SSPL-1.0", "EUPL-1.1", "EUPL-1.2", "OSL-3.0", "CPAL-1.0");

    private static final Set<String> FORBIDDEN_LICENSES = Set.of(
            "COMMERCIAL", "PROPRIETARY", "NON-COMMERCIAL", "CC-BY-NC-4.0", "BUSL-1.1", "COMMONS-CLAUSE");

    public static LicenseRiskCategory classify(String licenseExpression) {
        if (licenseExpression == null || licenseExpression.isBlank()) {
            return UNKNOWN;
        }
        String normalized = licenseExpression.trim().toUpperCase(Locale.ROOT)
                .replaceAll("[\\(\\)]", "")
                .trim();

        if (FORBIDDEN_LICENSES.contains(normalized) || normalized.contains("PROPRIETARY") || normalized.contains("NON-COMMERCIAL")) {
            return FORBIDDEN;
        }
        if (STRONG_COPYLEFT_LICENSES.contains(normalized) || normalized.startsWith("GPL") || normalized.startsWith("AGPL") || normalized.startsWith("SSPL")) {
            return STRONG_COPYLEFT;
        }
        if (WEAK_COPYLEFT_LICENSES.contains(normalized) || normalized.startsWith("LGPL") || normalized.startsWith("MPL") || normalized.startsWith("EPL") || normalized.startsWith("CDDL")) {
            return WEAK_COPYLEFT;
        }
        if (PERMISSIVE_LICENSES.contains(normalized) || normalized.contains("MIT") || normalized.contains("APACHE") || normalized.contains("BSD") || normalized.contains("ISC")) {
            return PERMISSIVE;
        }
        return UNKNOWN;
    }
}
