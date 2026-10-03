package com.asmolabs.vectispire.common.domain.sbom;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.sbom.InventoryCompletion.Completed;
import com.asmolabs.vectispire.common.domain.sbom.InventoryCompletion.Plan;
import com.asmolabs.vectispire.common.domain.sbom.InventoryCompletion.Scanned;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("a build's SBOM completing a scanner's inventory")
class InventoryCompletionTest {

    private static BuildSbom.Component built(String name, String version, String purl) {
        return new BuildSbom.Component(name, version, purl, "library", "Apache-2.0");
    }

    @Test
    @DisplayName("the build's version replaces the scanner's UNKNOWN, a transitive library is added, the scanner's own stay")
    void union() {
        List<Scanned> scanned = List.of(
                new Scanned(1, "spring-core", "UNKNOWN", "pkg:maven/org.springframework/spring-core"),
                new Scanned(2, "left-pad", "1.3.0", "pkg:npm/left-pad@1.3.0"),
                new Scanned(3, "no-purl", "", null));
        BuildSbom.Component core = built("spring-core", "6.1.14", "pkg:maven/org.springframework/spring-core@6.1.14");
        BuildSbom.Component jcl = built("spring-jcl", "6.1.14", "pkg:maven/org.springframework/spring-jcl@6.1.14");

        Plan plan = InventoryCompletion.of(scanned, List.of(core, jcl));

        assertThat(plan.completed()).containsExactly(
                new Completed(1, "6.1.14", "pkg:maven/org.springframework/spring-core@6.1.14", "Apache-2.0"));
        assertThat(plan.added()).containsExactly(jcl);
    }

    @Test
    @DisplayName("the build's stated version wins over the scanner's stated one; a build stating none leaves the scanner's")
    void buildWins() {
        Plan plan = InventoryCompletion.of(
                List.of(new Scanned(1, "a", "1.0", "pkg:maven/g/a@1.0"), new Scanned(2, "b", "2.0", "pkg:maven/g/b@2.0")),
                List.of(built("a", "1.1", "pkg:maven/g/a@1.1"), built("b", null, "pkg:maven/g/b")));

        assertThat(plan.completed()).containsExactly(
                new Completed(1, "1.1", "pkg:maven/g/a@1.1", "Apache-2.0"),
                new Completed(2, "2.0", "pkg:maven/g/b@2.0", "Apache-2.0"));
        assertThat(plan.added()).isEmpty();
    }

    @Test
    @DisplayName("of several build versions a scanner row takes its own, else the first; none is dropped")
    void severalVersions() {
        BuildSbom.Component one = built("a", "1.0", "pkg:maven/g/a@1.0");
        BuildSbom.Component two = built("a", "2.0", "pkg:maven/g/a@2.0");

        Plan exact = InventoryCompletion.of(List.of(new Scanned(1, "a", "2.0", "pkg:maven/g/a@2.0")), List.of(one, two));
        assertThat(exact.completed()).extracting(Completed::version).containsExactly("2.0");
        assertThat(exact.added()).containsExactly(one);

        Plan unknown = InventoryCompletion.of(List.of(new Scanned(1, "a", "UNKNOWN", "pkg:maven/g/a")), List.of(one, two));
        assertThat(unknown.completed()).extracting(Completed::version).containsExactly("1.0");
        assertThat(unknown.added()).containsExactly(two);
    }

    @Test
    @DisplayName("a name alone matches nothing: a scanner row without a purl is never completed")
    void nameIsNoIdentity() {
        Plan plan = InventoryCompletion.of(List.of(new Scanned(1, "a", "UNKNOWN", null)),
                List.of(built("a", "1.0", "pkg:maven/g/a@1.0")));

        assertThat(plan.completed()).isEmpty();
        assertThat(plan.added()).hasSize(1);
    }
}
