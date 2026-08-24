package com.asmolabs.vectispire.common.domain.targets;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

@DisplayName("scan targets")
class TargetsTest {

    @Nested
    @DisplayName("repository URLs")
    class RepositoryUrls {

        @ParameterizedTest(name = "accepts {0}")
        @ValueSource(strings = {
            "https://github.com/org/project.git",
            "ssh://git@github.com/org/project.git",
            "git://example.com/project",
            "git@github.com:org/project.git"
        })
        void acceptsTheTwoForms(String url) {
            assertThat(RepositoryUrl.validate(url)).isEmpty();
        }

        @ParameterizedTest(name = "refuses {0}")
        @ValueSource(strings = {
            // Would clone a local path on the agent.
            "file:///etc/passwd",
            // `ext::` makes git itself run an arbitrary command — the reason this is an
            // allowlist and not a denylist.
            "ext::sh -c whoami",
            "https:///no-host",
            "not a url at all",
            ""
        })
        void refusesEverythingElse(String url) {
            // This value lands in a `git clone` run by an agent. An uncontrolled one there is
            // arbitrary code execution on the machine doing the scanning.
            assertThat(RepositoryUrl.validate(url)).isPresent();
        }

        @ParameterizedTest(name = "{0} is displayed as {1}")
        @CsvSource({
            "https://github.com/org/project.git, org/project",
            "https://github.com/org/project/, org/project",
            "git@github.com:team/subgroup/project.git, subgroup/project",
            "ssh://git@host/org/project, org/project"
        })
        void shortensToOrgAndProject(String url, String expected) {
            // The name belongs to the server. One screen shortened it client-side while
            // another showed it whole, so the same repository carried two names depending on
            // the page and nothing told the user they were the same thing.
            assertThat(RepositoryUrl.shortName(url)).isEqualTo(expected);
        }

        @Test
        @DisplayName("a chosen name wins over the shortened URL")
        void chosenNameWins() {
            assertThat(RepositoryUrl.displayName("  Billing API ", "https://github.com/org/project"))
                    .isEqualTo("Billing API");
            assertThat(RepositoryUrl.displayName("   ", "https://github.com/org/project")).isEqualTo("org/project");
            assertThat(RepositoryUrl.displayName(null, "https://github.com/org/project")).isEqualTo("org/project");
        }
    }

    @Nested
    @DisplayName("image references")
    class ImageReferences {

        @Test
        @DisplayName("accepts a plain reference, with or without a registry")
        void acceptsPlainReferences() {
            assertThat(new ImageReference(null, "library/nginx", "1.27").validate()).isEmpty();
            assertThat(new ImageReference("registry.example.com:5000", "team/api", "latest").validate()).isEmpty();
        }

        @Test
        @DisplayName("accepts a digest in place of a tag")
        void acceptsDigests() {
            assertThat(new ImageReference(null, "nginx", "sha256:" + "a".repeat(64)).validate()).isEmpty();
        }

        @ParameterizedTest(name = "refuses the image name [{0}]")
        @ValueSource(strings = {"Nginx", "nginx image", "", "-nginx", "nginx/"})
        void refusesBadImageNames(String name) {
            // Upper case is refused by the registry itself; saying so at entry beats finding
            // out at the first scan. A space is worse — it shifts the container command line's
            // arguments.
            assertThat(new ImageReference(null, name, "latest").validate()).isPresent();
        }

        @ParameterizedTest(name = "refuses the tag [{0}]")
        @ValueSource(strings = {"", ".leading-dot", "tag with space", "sha256:tooshort"})
        void refusesBadTags(String tag) {
            assertThat(new ImageReference(null, "nginx", tag).validate()).isPresent();
        }

        @Test
        @DisplayName("refuses a registry that is not a host")
        void refusesBadRegistries() {
            assertThat(new ImageReference("not a host", "nginx", "latest").validate()).isPresent();
        }

        @Test
        @DisplayName("joins a digest with @ and a tag with :")
        void formatsCorrectly() {
            // Getting this wrong produces a reference the registry rejects, at pull time, on
            // the agent, far from here.
            String digest = "sha256:" + "b".repeat(64);

            assertThat(new ImageReference("reg.io", "team/api", "1.2").format()).isEqualTo("reg.io/team/api:1.2");
            assertThat(new ImageReference(null, "nginx", digest).format()).isEqualTo("nginx@" + digest);
        }

        @Test
        @DisplayName("the display name keeps the whole value, because it is also a search key")
        void displayNameIsNotShortened() {
            assertThat(new ImageReference("reg.io", "team/api", "1.2").displayName()).isEqualTo("team/api:1.2");
        }
    }

    @Nested
    @DisplayName("target identity")
    class Identity {

        @Test
        @DisplayName("a repository and a container sharing an id are different targets")
        void sameIdDifferentTarget() {
            assertThat(new ScanTarget.Repository(1)).isNotEqualTo(new ScanTarget.Container(1));
            assertThat(new ScanTarget.Repository(1).fingerprintKey()).isEqualTo("repo:1");
            assertThat(new ScanTarget.Container(1).fingerprintKey()).isEqualTo("container:1");
        }
    }
}
