package com.asmolabs.vectispire.core.inventory;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.List;

/**
 * The licence an SBOM artifact declares — read, never guessed.
 *
 * <p><b>One reading for the licence inventory and the SBOM diff.</b> The diff kept a copy of its own that
 * read the first entry only and, finding none, guessed from the package's name: "mit" matched {@code
 * commit} and {@code summit}, {@code spring-} meant Apache-2.0, "gpl" GPL-3.0. A licence change between
 * two scans could then be one the guess invented, and a component nobody had declared a licence for was
 * shown with one. The inventory had already dropped that guess; this is its reading, shared.
 */
final class SbomLicences {

    /** What an undeclared licence is recorded as: unknown, and nothing more. */
    static final String UNDECLARED = "UNKNOWN";

    private SbomLicences() {}

    /**
     * Every licence the artifact declares, joined by {@code OR} — a Syft artifact's {@code licenses}, each a
     * string, an SPDX expression, a value or a CycloneDX {@code license} id or name — or {@code null} when
     * it declares none.
     */
    static String declared(JsonNode artifact) {
        JsonNode licenses = artifact.path("licenses");
        if (licenses.isArray() && !licenses.isEmpty()) {
            List<String> values = new ArrayList<>();
            for (JsonNode lic : licenses) {
                if (lic.isTextual()) {
                    values.add(lic.asText());
                } else if (lic.isObject()) {
                    if (lic.hasNonNull("spdxExpression")) {
                        values.add(lic.path("spdxExpression").asText());
                    } else if (lic.hasNonNull("value")) {
                        values.add(lic.path("value").asText());
                    } else if (lic.has("license") && lic.path("license").hasNonNull("id")) {
                        values.add(lic.path("license").path("id").asText());
                    } else if (lic.has("license") && lic.path("license").hasNonNull("name")) {
                        values.add(lic.path("license").path("name").asText());
                    }
                }
            }
            if (!values.isEmpty()) {
                return String.join(" OR ", values);
            }
        }
        return null;
    }

    /** {@link #declared}, or {@link #UNDECLARED} when the artifact declares none. */
    static String declaredOrUnknown(JsonNode artifact) {
        String license = declared(artifact);
        return license == null || license.isBlank() || UNDECLARED.equalsIgnoreCase(license) ? UNDECLARED : license;
    }
}
