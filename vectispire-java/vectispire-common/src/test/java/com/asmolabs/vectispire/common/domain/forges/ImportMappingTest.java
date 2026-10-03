package com.asmolabs.vectispire.common.domain.forges;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.forges.ImportMapping.Placement;
import com.asmolabs.vectispire.common.domain.forges.ImportMapping.Rule;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("the import's mapping into solutions and projects (decision 0037 §4)")
class ImportMappingTest {

    @Test
    @DisplayName("GitLab: the top-level group is the solution, the parent group below it the project")
    void gitlabProposal() {
        assertThat(ImportMapping.proposed(ForgeKind.GITLAB, "acme/backend/payments", "api", false))
                .isEqualTo(new Placement("acme", "backend/payments"));
        assertThat(ImportMapping.proposed(ForgeKind.GITLAB, "acme/backend", "api", false))
                .isEqualTo(new Placement("acme", "backend"));
        assertThat(ImportMapping.proposed(ForgeKind.GITLAB, "acme", "api", false))
                .as("directly under the top-level group: a project named after it")
                .isEqualTo(new Placement("acme", "acme"));
    }

    @Test
    @DisplayName("GitHub: the organisation is the solution, each repository its own project")
    void githubProposal() {
        assertThat(ImportMapping.proposed(ForgeKind.GITHUB, "acme", "api", false)).isEqualTo(new Placement("acme", "api"));
    }

    @Test
    @DisplayName("a personal namespace is filed nowhere")
    void personal() {
        assertThat(ImportMapping.proposed(ForgeKind.GITLAB, "ada", "notes", true)).isEqualTo(Placement.NONE);
        assertThat(ImportMapping.proposed(ForgeKind.GITHUB, "ada", "notes", true)).isEqualTo(Placement.NONE);
        assertThat(Placement.NONE.filed()).isFalse();
    }

    @Test
    @DisplayName("rules: the deepest namespace's word on each field, then the repository's own")
    void mostSpecificWins() {
        ImportMapping mapping = ImportMapping.of(List.of(
                new Rule("acme", null, "Acme Corp", null, null),
                new Rule("acme/backend", null, null, "Backend", null),
                new Rule(null, "42", null, "Payments API", null)));

        assertThat(mapping.place(ForgeKind.GITLAB, "7", "acme/backend/payments", "api", false).placement())
                .as("the solution renamed at the top, the project at the subgroup")
                .isEqualTo(new Placement("Acme Corp", "Backend"));
        assertThat(mapping.place(ForgeKind.GITLAB, "42", "acme/backend/payments", "api", false).placement())
                .isEqualTo(new Placement("Acme Corp", "Payments API"));
        assertThat(mapping.place(ForgeKind.GITLAB, "8", "acme/frontend", "web", false).placement())
                .as("a sibling keeps its proposed project")
                .isEqualTo(new Placement("Acme Corp", "frontend"));
        assertThat(mapping.place(ForgeKind.GITLAB, "9", "acmes/x", "web", false).placement())
                .as("covered by whole segments, not by prefix")
                .isEqualTo(new Placement("acmes", "x"));
    }

    @Test
    @DisplayName("no project, and a personal repository filed by a rule naming both")
    void noProject() {
        ImportMapping mapping = ImportMapping.of(List.of(
                new Rule("acme/legacy", null, null, null, true),
                new Rule(null, "5", "Personal", "Ada", null)));
        assertThat(mapping.place(ForgeKind.GITLAB, "1", "acme/legacy/old", "x", false).placement())
                .isEqualTo(Placement.NONE);
        ImportMapping.Outcome personal = mapping.place(ForgeKind.GITLAB, "5", "ada", "notes", true);
        assertThat(personal.placement()).isEqualTo(new Placement("Personal", "Ada"));
        assertThat(personal.refusal()).isEmpty();
    }

    @Test
    @DisplayName("a placement it cannot apply is a refusal against the repository, not a guess")
    void halfAPlacement() {
        ImportMapping projectOnly = ImportMapping.of(List.of(new Rule(null, "5", null, "Notes", null)));
        assertThat(projectOnly.place(ForgeKind.GITLAB, "5", "ada", "notes", true).refusal())
                .hasValueSatisfying(refusal -> assertThat(refusal).contains("name the solution"));
        ImportMapping solutionOnly = ImportMapping.of(List.of(new Rule(null, "5", "Personal", null, null)));
        assertThat(solutionOnly.place(ForgeKind.GITLAB, "5", "ada", "notes", true).refusal())
                .hasValueSatisfying(refusal -> assertThat(refusal).contains("name the project"));
        String deep = "acme/" + "x".repeat(101);
        assertThat(ImportMapping.PROPOSED.place(ForgeKind.GITLAB, "6", deep, "api", false).refusal())
                .as("a proposed name past the column's hundred characters")
                .hasValueSatisfying(refusal -> assertThat(refusal).contains("longer than 100"));
    }

    @Test
    @DisplayName("the rules are refused in words")
    void refusals() {
        assertThatThrownBy(() -> ImportMapping.of(List.of(new Rule("a", "1", "S", null, null))))
                .isInstanceOf(InvalidInputException.class).hasMessageContaining("not both");
        assertThatThrownBy(() -> ImportMapping.of(List.of(new Rule(null, null, "S", null, null))))
                .isInstanceOf(InvalidInputException.class).hasMessageContaining("not both and not neither");
        assertThatThrownBy(() -> ImportMapping.of(List.of(new Rule("a", null, null, null, null))))
                .isInstanceOf(InvalidInputException.class).hasMessageContaining("changes nothing");
        assertThatThrownBy(() -> ImportMapping.of(List.of(new Rule("a", null, "S", null, true))))
                .isInstanceOf(InvalidInputException.class).hasMessageContaining("choose");
        assertThatThrownBy(() -> ImportMapping.of(List.of(new Rule("A", null, "S", null, null),
                        new Rule("a/", null, "T", null, null))))
                .isInstanceOf(InvalidInputException.class).hasMessageContaining("Two mapping rules");
        assertThatThrownBy(() -> ImportMapping.of(List.of(new Rule("a", null, "x".repeat(101), null, null))))
                .isInstanceOf(InvalidInputException.class).hasMessageContaining("longer than 100");
        assertThatThrownBy(() -> ImportMapping.of(List.of(new Rule("a", null, " ", null, null))))
                .isInstanceOf(InvalidInputException.class).hasMessageContaining("is required");
    }
}
