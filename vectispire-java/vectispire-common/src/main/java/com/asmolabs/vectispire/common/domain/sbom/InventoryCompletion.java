package com.asmolabs.vectispire.common.domain.sbom;

import com.asmolabs.vectispire.common.domain.eol.Purls;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * How a build's SBOM completes the inventory a scanner wrote of one scan — the precedence rule, in one
 * place.
 *
 * <h2>The rule</h2>
 *
 * <ol>
 *   <li><b>Union.</b> Every component the scanner listed stays; every component the build lists and the
 *       scanner does not is added ({@link ComponentOrigin#BUILD}). The scanner sees what no build
 *       declares — a front end beside the Maven tree, a vendored binary — and the build sees what the
 *       scanner cannot: a transitive library, a version a parent BOM manages.
 *   <li><b>One package, matched by its purl</b> without version, qualifiers or subpath ({@link
 *       Purls#normalize}). A scanner row with no purl matches nothing: a name alone is not an identity
 *       across ecosystems, and a wrong match would hide a component behind another's version.
 *   <li><b>The build's stated version wins</b> where both list the package ({@link ComponentOrigin#BOTH}),
 *       whatever the scanner wrote — {@code UNKNOWN}, nothing, or a version read off a manifest. The build
 *       resolved the graph and packaged what it states; the scanner read declarations. The scanner's
 *       version is kept beside it, shown, and restored if a later build SBOM no longer lists the package.
 *       A build that states no version leaves the scanner's.
 *   <li><b>Several versions of one package in the build</b> — an aggregate BOM whose modules resolved it
 *       differently: a scanner row is completed by the one at its own stated version, else by the first
 *       the document lists, and the others are added. Nothing the build stated is dropped.
 * </ol>
 *
 * <p>The licence the build declares is kept with each component it lists; the scanner's own licences
 * stay where they always were, in its SBOM.
 */
public final class InventoryCompletion {

    private InventoryCompletion() {}

    /** A row the scanner wrote, as the scanner wrote it — before any completion. */
    public record Scanned(long id, String name, String version, String purl) {}

    /**
     * A scanner row the build also lists: what it becomes.
     *
     * @param version the build's version where it states one, else the scanner's
     * @param purl the build's purl where it states a version, else the scanner's
     */
    public record Completed(long id, String version, String purl, String license) {}

    /** @param completed the scanner rows the build also lists; @param added what only the build lists */
    public record Plan(List<Completed> completed, List<BuildSbom.Component> added) {}

    public static Plan of(List<Scanned> scanned, List<BuildSbom.Component> build) {
        Map<String, List<BuildSbom.Component>> byIdentity = new LinkedHashMap<>();
        for (BuildSbom.Component component : build) {
            identity(component.purl()).ifPresent(
                    identity -> byIdentity.computeIfAbsent(identity, key -> new ArrayList<>()).add(component));
        }

        Set<BuildSbom.Component> used = new HashSet<>();
        List<Completed> completed = new ArrayList<>();
        for (Scanned row : scanned) {
            Optional<String> identity = identity(row.purl());
            List<BuildSbom.Component> candidates = identity.map(byIdentity::get).orElse(null);
            if (candidates == null) {
                continue;
            }
            BuildSbom.Component chosen = candidates.stream()
                    .filter(candidate -> stated(row.version()) && row.version().equals(candidate.version()))
                    .findFirst()
                    .orElse(candidates.getFirst());
            used.add(chosen);
            boolean buildStates = stated(chosen.version());
            completed.add(new Completed(row.id(),
                    buildStates ? chosen.version() : row.version(),
                    buildStates && chosen.purl() != null ? chosen.purl() : row.purl(),
                    chosen.license()));
        }

        List<BuildSbom.Component> added = new ArrayList<>();
        for (BuildSbom.Component component : build) {
            if (!used.contains(component)) {
                added.add(component);
            }
        }
        return new Plan(List.copyOf(completed), List.copyOf(added));
    }

    /** Syft's literal for a version it could not tell, as {@code MeasurementFacts.Component} reads it. */
    private static boolean stated(String version) {
        return version != null && !version.isBlank() && !version.strip().toUpperCase(Locale.ROOT).equals("UNKNOWN");
    }

    private static Optional<String> identity(String purl) {
        return purl == null || purl.isBlank() ? Optional.empty() : Optional.of(Purls.normalize(purl));
    }
}
