package com.asmolabs.zanshin.common.domain.dependencies;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("dependency directness")
class DependencyGraphTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static JsonNode json(String text) {
        try {
            return MAPPER.readTree(text);
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    /** `lib-a` is declared; `lib-b` is pulled in by it. */
    private static final JsonNode SBOM = json("""
            {"artifacts": [
               {"id": "a1", "name": "lib-a", "version": "1.0", "purl": "pkg:npm/lib-a@1.0"},
               {"id": "b1", "name": "lib-b", "version": "2.0", "purl": "pkg:npm/lib-b@2.0"}],
             "artifactRelationships": [{"type": "dependency-of", "parent": "b1", "child": "a1"}]}""");

    @Test
    @DisplayName("tells a root of the graph from what something else pulls in")
    void distinguishesRootsFromLeaves() {
        DependencyGraph graph = new DependencyGraph(SBOM);

        assertThat(graph.of("pkg:npm/lib-a@1.0", null, null)).isEqualTo(Directness.DIRECT);
        assertThat(graph.of("pkg:npm/lib-b@2.0", null, null)).isEqualTo(Directness.TRANSITIVE);
    }

    @Test
    @DisplayName("answers unknown for everything when the SBOM carries no edge")
    void noEdgesMeansNoAnswer() {
        // The important case. With no edges *every* package looks like a root, which would
        // label a whole image "direct dependencies" — a confident wrong answer on the field
        // that decides what to fix first, which is worse than silence.
        DependencyGraph graph = new DependencyGraph(json("""
                {"artifacts": [{"id": "a1", "name": "lib-a", "version": "1.0", "purl": "pkg:npm/lib-a@1.0"}]}"""));

        assertThat(graph.isAvailable()).isFalse();
        assertThat(graph.of("pkg:npm/lib-a@1.0", null, null)).isEqualTo(Directness.UNKNOWN);
    }

    @Test
    @DisplayName("answers unknown on an absent or empty SBOM")
    void emptySbomIsUnknown() {
        assertThat(new DependencyGraph(null).of("pkg:npm/x@1", null, null)).isEqualTo(Directness.UNKNOWN);
        assertThat(new DependencyGraph(json("{\"artifacts\": []}")).of("pkg:npm/x@1", null, null))
                .isEqualTo(Directness.UNKNOWN);
    }

    @Test
    @DisplayName("falls back to name and version when the cataloger produced no purl")
    void fallsBackToNameAndVersion() {
        DependencyGraph graph = new DependencyGraph(json("""
                {"artifacts": [{"id": "a1", "name": "lib-a", "version": "1.0"},
                               {"id": "b1", "name": "lib-b", "version": "2.0"}],
                 "artifactRelationships": [{"type": "dependency-of", "parent": "b1", "child": "a1"}]}"""));

        assertThat(graph.of(null, "lib-a", "1.0")).isEqualTo(Directness.DIRECT);
        assertThat(graph.of(null, "lib-b", "2.0")).isEqualTo(Directness.TRANSITIVE);
    }

    @Test
    @DisplayName("never matches on the name alone")
    void neverMatchesOnNameAlone() {
        // Two versions of one package can fall on either side: one declared, the other
        // dragged in. A name-only match is a coin toss on a field about to be prioritized by.
        DependencyGraph graph = new DependencyGraph(json("""
                {"artifacts": [{"id": "a1", "name": "lib", "version": "1.0"},
                               {"id": "a2", "name": "lib", "version": "2.0"}],
                 "artifactRelationships": [{"type": "dependency-of", "parent": "a2", "child": "a1"}]}"""));

        assertThat(graph.of(null, "lib", "1.0")).isEqualTo(Directness.DIRECT);
        assertThat(graph.of(null, "lib", "2.0")).isEqualTo(Directness.TRANSITIVE);
        assertThat(graph.of(null, "lib", null)).isEqualTo(Directness.UNKNOWN);
    }

    @Test
    @DisplayName("answers unknown for a package the SBOM does not contain")
    void unknownPackageIsUnknown() {
        assertThat(new DependencyGraph(SBOM).of("pkg:npm/absent@9.9", null, null)).isEqualTo(Directness.UNKNOWN);
    }

    @Test
    @DisplayName("an unknown directness prints nothing rather than the word unknown")
    void unknownHasNoLabel() {
        // A column filled with "unknown" reads as a finding about the dependency, when the
        // honest statement is that we have nothing to say about it.
        assertThat(Directness.UNKNOWN.label()).isEmpty();
        assertThat(Directness.DIRECT.label()).isEqualTo("direct");
        assertThat(Directness.TRANSITIVE.label()).isEqualTo("transitive");
    }
}
