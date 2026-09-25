package com.asmolabs.vectispire.common.domain.licenses;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/**
 * Policy governing allowed open source license categories and specific exemptions.
 *
 * <p><b>Normalized on construction, whoever constructs it.</b> This record is also the request
 * body of {@code PUT /licenses/policy}, so Jackson builds it straight from the wire: a missing set
 * arrived as {@code null} and a {@code [null]} entry as a null element, and the store dereferenced
 * both — a 500. And {@link #isCompliant} upper-cases the licence it is asked about but compared it
 * with the entries as typed, so an exemption written {@code "mit"} never matched anything. The
 * compact constructor therefore drops nulls and blanks, and stores every identifier trimmed and in
 * capitals — on the wire, and on the read from the database alike.
 *
 * <p>Sorted, so that the stored string and the JSON answer are the same from one save to the next.
 */
public record LicensePolicy(
        Set<LicenseRiskCategory> disallowedCategories,
        Set<String> explicitlyAllowedLicenses,
        Set<String> explicitlyDisallowedLicenses) {

    public LicensePolicy {
        disallowedCategories = categories(disallowedCategories);
        explicitlyAllowedLicenses = identifiers(explicitlyAllowedLicenses);
        explicitlyDisallowedLicenses = identifiers(explicitlyDisallowedLicenses);
    }

    public static LicensePolicy defaultPolicy() {
        return new LicensePolicy(
                Set.of(LicenseRiskCategory.STRONG_COPYLEFT, LicenseRiskCategory.FORBIDDEN),
                Set.of(),
                Set.of());
    }

    public boolean isCompliant(String license, LicenseRiskCategory category) {
        // Locale.ROOT: under a Turkish default locale, "mit" upper-cases to "MİT" and matches nothing.
        String normalized = license == null ? null : license.trim().toUpperCase(Locale.ROOT);
        if (normalized != null && explicitlyDisallowedLicenses.contains(normalized)) {
            return false;
        }
        if (normalized != null && explicitlyAllowedLicenses.contains(normalized)) {
            return true;
        }
        return !disallowedCategories.contains(category);
    }

    private static Set<LicenseRiskCategory> categories(Set<LicenseRiskCategory> raw) {
        EnumSet<LicenseRiskCategory> kept = EnumSet.noneOf(LicenseRiskCategory.class);
        if (raw != null) {
            raw.stream().filter(Objects::nonNull).forEach(kept::add);
        }
        return Collections.unmodifiableSet(kept);
    }

    private static Set<String> identifiers(Set<String> raw) {
        TreeSet<String> kept = new TreeSet<>();
        if (raw != null) {
            raw.stream()
                    .filter(Objects::nonNull)
                    .map(entry -> entry.trim().toUpperCase(Locale.ROOT))
                    .filter(entry -> !entry.isEmpty())
                    .forEach(kept::add);
        }
        return Collections.unmodifiableSortedSet(kept);
    }
}
