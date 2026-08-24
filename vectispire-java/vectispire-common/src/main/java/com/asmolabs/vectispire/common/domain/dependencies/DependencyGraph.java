package com.asmolabs.vectispire.common.domain.dependencies;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Which dependencies the project actually asked for.
 *
 * <p>Every vulnerability used to arrive with the same amount of information about <em>what to
 * do</em>: none. A critical CVE in a package declared in the manifest is fixed this afternoon
 * by changing one line; the same CVE four levels down waits on an upstream release and may
 * need a pin, a fork, or the decision to accept the risk. Ranked identically they produce a
 * backlog nobody finishes — and the transitive ones, being the majority, bury the handful that
 * are actionable today.
 *
 * <p><b>Syft already answers this and the answer was being thrown away.</b> The SBOM carries
 * {@code dependency-of} relationships, where the <em>parent</em> is the dependency and the
 * <em>child</em> is what depends on it. A package that never appears as a parent is a root of
 * the graph: exactly "the project declared this".
 *
 * <p><b>The important part is what happens when the graph is absent.</b> Some catalogers emit
 * no edges at all, and then <em>every</em> package looks like a root — which would label a
 * whole container image "direct dependencies". That is worse than saying nothing: it is a
 * confident wrong answer on the one field meant to decide what to fix first. With no edges,
 * everything is {@link Directness#UNKNOWN}.
 */
public final class DependencyGraph {

    private static final String DEPENDENCY_OF = "dependency-of";

    private final Map<String, Boolean> byPurl = new HashMap<>();
    private final Map<String, Boolean> byNameAndVersion = new HashMap<>();
    private final boolean available;

    public DependencyGraph(JsonNode sbom) {
        JsonNode artifacts = sbom == null ? null : sbom.path("artifacts");
        if (artifacts == null || !artifacts.isArray() || artifacts.isEmpty()) {
            this.available = false;
            return;
        }

        Set<String> dependedUpon = new HashSet<>();
        JsonNode relationships = sbom.path("artifactRelationships");
        if (relationships.isArray()) {
            for (JsonNode relation : relationships) {
                if (DEPENDENCY_OF.equals(relation.path("type").asText(null))) {
                    String parent = relation.path("parent").asText(null);
                    if (parent != null && !parent.isEmpty()) {
                        dependedUpon.add(parent);
                    }
                }
            }
        }

        if (dependedUpon.isEmpty()) {
            this.available = false;
            return;
        }
        this.available = true;

        for (JsonNode artifact : artifacts) {
            String id = artifact.path("id").asText(null);
            boolean direct = id != null && !dependedUpon.contains(id);

            // A purl already carries the version, so two versions of one package keep distinct
            // answers — which matters, because one may be declared and the other dragged in.
            String purl = artifact.path("purl").asText(null);
            if (purl != null && !purl.isEmpty()) {
                byPurl.merge(purl, direct, Boolean::logicalOr);
            }
            String name = artifact.path("name").asText(null);
            if (name != null && !name.isEmpty()) {
                byNameAndVersion.merge(key(name, artifact.path("version").asText("")), direct, Boolean::logicalOr);
            }
        }
    }

    /** Did the graph carry any edges at all? If not, every answer is {@link Directness#UNKNOWN}. */
    public boolean isAvailable() {
        return available;
    }

    /**
     * The answer for one package.
     *
     * <p><b>The purl first</b>: it is the ecosystem-qualified identity, and it is what the
     * vulnerability matches and the license findings carry. Name plus version is the fallback
     * for a cataloger that produced no purl.
     *
     * <p>Matching on the name alone is <b>deliberately not attempted</b>: two versions of one
     * package can fall on either side of this answer, so a name-only match is a coin toss on a
     * field an operator is about to prioritize by.
     */
    public Directness of(String purl, String name, String version) {
        if (!available) {
            return Directness.UNKNOWN;
        }

        if (purl != null && !purl.isEmpty()) {
            Boolean direct = byPurl.get(purl);
            if (direct != null) {
                return Directness.of(direct);
            }
        }
        if (name != null && !name.isEmpty()) {
            Boolean direct = byNameAndVersion.get(key(name, version == null ? "" : version));
            if (direct != null) {
                return Directness.of(direct);
            }
        }
        return Directness.UNKNOWN;
    }

    /** How many packages are direct — for the log, and for reassurance about the graph. */
    public long directCount() {
        return byPurl.values().stream().filter(Boolean::booleanValue).count();
    }

    private static String key(String name, String version) {
        return name + "@" + version;
    }
}
