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
            "MIT", "APACHE-2.0", "APACHE-1.1", "APACHE-2.0-WITH-LLVM-EXCEPTION", "BSD-2-CLAUSE", "BSD-3-CLAUSE", "BSD-4-CLAUSE",
            "ISC", "CC0-1.0", "UNLICENSE", "0BSD", "ZLIB", "POSTGRESQL", "WTFPL", "JSON", "PYTHON-2.0", "ARTISTIC-2.0",
            "RUBY", "OPENSSL", "ECL-2.0", "UPL-1.0", "BSL-1.0", "BLUEOAK-1.0.0", "X11", "FREEIMAGE", "OFL-1.1", "EDL-1.0", "CC-BY-4.0", "CC-BY-3.0");

    private static final Set<String> WEAK_COPYLEFT_LICENSES = Set.of(
            "LGPL-2.0-ONLY", "LGPL-2.0-OR-LATER", "LGPL-2.1-ONLY", "LGPL-2.1-OR-LATER", "LGPL-3.0-ONLY", "LGPL-3.0-OR-LATER",
            "LGPL-2.0", "LGPL-2.1", "LGPL-3.0", "MPL-1.0", "MPL-1.1", "MPL-2.0", "CDDL-1.0", "CDDL-1.1", "EPL-1.0", "EPL-2.0",
            "CPL-1.0", "APSL-2.0", "MS-PL", "MS-RL", "IPA", "SUNPRO");

    private static final Set<String> STRONG_COPYLEFT_LICENSES = Set.of(
            "GPL-1.0-ONLY", "GPL-1.0-OR-LATER", "GPL-2.0-ONLY", "GPL-2.0-OR-LATER", "GPL-3.0-ONLY", "GPL-3.0-OR-LATER",
            "GPL-1.0", "GPL-2.0", "GPL-3.0", "AGPL-1.0", "AGPL-3.0", "AGPL-3.0-ONLY", "AGPL-3.0-OR-LATER",
            "SSPL-1.0", "EUPL-1.1", "EUPL-1.2", "OSL-1.0", "OSL-2.0", "OSL-3.0", "CPAL-1.0", "QPL-1.0", "RPL-1.5", "SLEEPYCAT", "CECILL-2.1");

    private static final Set<String> FORBIDDEN_LICENSES = Set.of(
            "COMMERCIAL", "PROPRIETARY", "NON-COMMERCIAL", "CC-BY-NC-4.0", "CC-BY-NC-3.0", "CC-BY-NC-2.0",
            "BUSL-1.1", "COMMONS-CLAUSE", "SEE-LICENSE-IN-LICENSE", "UNLICENSED");

    public static LicenseRiskCategory classify(String licenseExpression) {
        if (licenseExpression == null || licenseExpression.isBlank()) {
            return UNKNOWN;
        }
        String normalized = licenseExpression.trim().toUpperCase(Locale.ROOT)
                .replaceAll("[\\(\\)]", "")
                .trim();

        if (FORBIDDEN_LICENSES.contains(normalized) || normalized.contains("PROPRIETARY") || normalized.contains("NON-COMMERCIAL") || normalized.contains("COMMONS-CLAUSE")) {
            return FORBIDDEN;
        }
        if (STRONG_COPYLEFT_LICENSES.contains(normalized) || normalized.startsWith("GPL") || normalized.startsWith("AGPL") || normalized.startsWith("SSPL") || normalized.startsWith("EUPL")) {
            return STRONG_COPYLEFT;
        }
        if (WEAK_COPYLEFT_LICENSES.contains(normalized) || normalized.startsWith("LGPL") || normalized.startsWith("MPL") || normalized.startsWith("EPL") || normalized.startsWith("CDDL")) {
            return WEAK_COPYLEFT;
        }
        if (PERMISSIVE_LICENSES.contains(normalized) || normalized.contains("MIT") || normalized.contains("APACHE") || normalized.contains("BSD") || normalized.contains("ISC") || normalized.contains("BOOST") || normalized.contains("ZLIB")) {
            return PERMISSIVE;
        }
        return UNKNOWN;
    }
}
