package com.asmolabs.vectispire.common.domain.licenses;

import com.asmolabs.vectispire.common.domain.sbom.Sbom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The forbidden licenses, evaluated over the SBOM Syft already produces.
 *
 * <p><b>No new tool is needed.</b> Syft records every component's licenses in the SBOM of any
 * scan, image or directory, so this is the evaluation of a rule over data already collected.
 *
 * <p><b>Nothing is reported until a list is configured.</b> Which licenses are forbidden is an
 * organizational decision, not a technical one: a default would impose a legal judgement in the
 * operator's place, on a screen they did not ask for it on.
 */
public record LicenseBlocklist(Set<String> forbidden) {

    public LicenseBlocklist {
        forbidden = Set.copyOf(forbidden);
    }

    /**
     * @param license as the SBOM spelled it, not as the list did — the operator reads the
     *     component's own declaration, and normalizing it would hide a mismatch worth seeing
     */
    public record Violation(String license, String packageName, String packageVersion, String purl) {}

    /** Parses the configured list. Comparison is case-insensitive, so the set is upper-cased. */
    public static LicenseBlocklist parse(String raw) {
        if (raw == null || raw.isBlank()) {
            return new LicenseBlocklist(Set.of());
        }
        return new LicenseBlocklist(Arrays.stream(raw.split(","))
                .map(entry -> entry.trim().toUpperCase(Locale.ROOT))
                .filter(entry -> !entry.isEmpty())
                .collect(Collectors.toUnmodifiableSet()));
    }

    public boolean isEmpty() {
        return forbidden.isEmpty();
    }

    /** The components one of whose licenses is on the list. */
    public List<Violation> violations(Sbom sbom) {
        if (forbidden.isEmpty()) {
            return List.of();
        }

        List<Violation> violations = new ArrayList<>();
        for (Sbom.Artifact artifact : sbom.artifacts()) {
            for (String license : artifact.licenses()) {
                if (forbidden.contains(license.toUpperCase(Locale.ROOT))) {
                    violations.add(new Violation(license, artifact.name(), artifact.version(), artifact.purl()));
                }
            }
        }
        return violations;
    }
}
