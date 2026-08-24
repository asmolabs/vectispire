package com.asmolabs.vectispire.common.domain.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * A Syft SBOM, read once into a shape the rules can use.
 *
 * <p>The scanner's output arrives as untyped JSON, and every rule that consumed it re-derived
 * the same fields with the same casts. Reading it here means the awkward parts of Syft's
 * schema are handled in one place instead of in each rule — and the awkward parts are real:
 *
 * <ul>
 *   <li><b>Licenses have had two shapes.</b> Syft emitted plain strings, then objects
 *       ({@code {"value": "MIT", "spdxExpression": "MIT"}}). Handling only one silences the
 *       license rule at Syft's next version bump — with no error, and with nobody noticing.
 *   <li><b>The operating system has no purl.</b> A container image's own distribution appears
 *       only in the {@code distro} block, which is why {@link #distro()} exists separately: it
 *       is the most useful end-of-life answer for an image, and no package-level lookup finds
 *       it.
 * </ul>
 *
 * <p>Anything unreadable becomes an empty list rather than an exception. A malformed SBOM
 * should cost the rules that depend on it, not the whole scan — and the analyzer that produced
 * it reports its own failure separately.
 */
public record Sbom(JsonNode root) {

    /** @param licenses already flattened from whichever shape Syft used */
    public record Artifact(String name, String version, String purl, List<String> licenses) {}

    /** @param id the lowercase distribution identifier, {@code debian}, {@code alpine}… */
    public record Distro(String id, String version, String label) {}

    public List<Artifact> artifacts() {
        JsonNode artifacts = root.path("artifacts");
        if (!artifacts.isArray()) {
            return List.of();
        }

        List<Artifact> parsed = new ArrayList<>(artifacts.size());
        for (JsonNode artifact : artifacts) {
            parsed.add(new Artifact(
                    text(artifact, "name"), text(artifact, "version"), text(artifact, "purl"), licensesOf(artifact)));
        }
        return parsed;
    }

    /** An image's own distribution, which carries no purl and is therefore read apart. */
    public Optional<Distro> distro() {
        JsonNode distro = root.path("distro");
        String id = text(distro, "id");
        String version = text(distro, "versionID");
        if (id == null || version == null) {
            return Optional.empty();
        }
        String label = text(distro, "name");
        return Optional.of(new Distro(id.toLowerCase(java.util.Locale.ROOT), version, label == null ? id : label));
    }

    private static List<String> licensesOf(JsonNode artifact) {
        JsonNode licenses = artifact.path("licenses");
        if (!licenses.isArray()) {
            return List.of();
        }

        List<String> values = new ArrayList<>();
        for (JsonNode entry : licenses) {
            if (entry.isTextual()) {
                addIfPresent(values, entry.asText());
            } else if (entry.isObject()) {
                // `value` first, `spdxExpression` as the fallback: both appear, and an entry
                // carrying only the expression is still a license.
                String value = text(entry, "value");
                addIfPresent(values, value != null ? value : text(entry, "spdxExpression"));
            }
        }
        return values;
    }

    private static void addIfPresent(List<String> values, String value) {
        if (value != null) {
            values.add(value);
        }
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.path(field);
        if (!value.isTextual()) {
            return null;
        }
        String text = value.asText().trim();
        return text.isEmpty() ? null : text;
    }
}
