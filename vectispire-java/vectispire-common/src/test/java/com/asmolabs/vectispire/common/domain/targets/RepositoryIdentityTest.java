package com.asmolabs.vectispire.common.domain.targets;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The rule that tells a repository already filed from a new one (decision 0037, §4). Each line of the
 * first table is a spelling an administrator has been seen to paste for the same repository; each of
 * the second a repository that only looks like it.
 */
@DisplayName("the identity of a repository")
class RepositoryIdentityTest {

    private static final String API = "gitlab.example.org/team/api";

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {
        "https://gitlab.example.org/team/api",
        "https://gitlab.example.org/team/api.git",
        "https://gitlab.example.org/team/api/",
        "https://gitlab.example.org/team/api.git/",
        "https://gitlab.example.org//team//api",
        // Case, in the host and in the path: `Acme/API` typed as `acme/api` is the duplicate this exists for.
        "https://GitLab.Example.ORG/Team/API.git",
        "https://gitlab.example.org./team/api",
        // The port, default or not: SSH and HTTPS reach one repository on two.
        "https://gitlab.example.org:443/team/api.git",
        "https://gitlab.example.org:8443/team/api.git",
        // A credential an old row still carries, and a login.
        "https://user:token@gitlab.example.org/team/api.git",
        "https://oauth2@gitlab.example.org/team/api.git",
        // SSH, in both of its spellings.
        "ssh://git@gitlab.example.org/team/api.git",
        "ssh://git@gitlab.example.org:2222/team/api.git",
        "ssh://gitlab.example.org/team/api",
        "git@gitlab.example.org:team/api.git",
        "git@gitlab.example.org:/team/api.git",
        "git@GITLAB.example.org:Team/Api",
        "git://gitlab.example.org/team/api.git",
        "  https://gitlab.example.org/team/api.git  "
    })
    void oneRepositoryWhateverTheSpelling(String url) {
        assertThat(RepositoryUrl.identity(url)).contains(API);
    }

    @ParameterizedTest(name = "{0} is not {1}")
    @CsvSource({
        "https://gitlab.example.org/team/api, https://gitlab.example.org/team/api-v2",
        "https://gitlab.example.org/team/api, https://gitlab.example.org/other/api",
        "https://gitlab.example.org/team/api, https://gitlab.example.org/team/sub/api",
        "https://gitlab.example.org/team/api, https://github.example.org/team/api",
        "https://gitlab.example.org/team/api, git@git.example.org:team/api.git",
        // `.git` is removed once, at the end only: a repository named `api.git` on a forge that allows it stays distinct.
        "https://gitlab.example.org/team/api, https://gitlab.example.org/team/api.git.git",
        "https://gitlab.example.org/team/api, https://gitlab.example.org/team.git/api"
    })
    void anotherRepositoryIsAnotherIdentity(String one, String other) {
        assertThat(RepositoryUrl.identity(one)).isPresent();
        assertThat(RepositoryUrl.identity(other)).isPresent().isNotEqualTo(RepositoryUrl.identity(one));
    }

    @ParameterizedTest(name = "none for \"{0}\"")
    @ValueSource(strings = {"", "not a url", "https:///no-host", "https://allowed.example#@other.example/repo.git"})
    void noHostNoIdentity(String url) {
        assertThat(RepositoryUrl.identity(url)).isEmpty();
    }

    @Test
    @DisplayName("no identity for no URL")
    void nullHasNone() {
        assertThat(RepositoryUrl.identity(null)).isEmpty();
    }

    @Test
    @DisplayName("a target is the repository, the branch and the sub-path: two directories of a monorepo are two targets")
    void subPathAndBranchSeparateTargets() {
        String root = RepositoryIdentity.of("git@gitlab.example.org:team/mono.git", "main", null).orElseThrow().guard();

        assertThat(RepositoryIdentity.of("https://gitlab.example.org/team/mono", "main", "").orElseThrow().guard())
                .as("the root, spelled twice")
                .isEqualTo(root);
        assertThat(RepositoryIdentity.of("https://gitlab.example.org/team/mono", " main ", " ").orElseThrow().guard())
                .isEqualTo(root);
        assertThat(RepositoryIdentity.of("https://gitlab.example.org/team/mono", null, null).orElseThrow().guard())
                .as("no branch is the default the form and the clone use")
                .isEqualTo(root);

        String api = RepositoryIdentity.of("https://gitlab.example.org/team/mono", "main", "services/api").orElseThrow().guard();
        assertThat(api).isNotEqualTo(root);
        assertThat(RepositoryIdentity.of("https://gitlab.example.org/team/mono", "main", "services/api/").orElseThrow().guard())
                .isEqualTo(api);
        assertThat(RepositoryIdentity.of("https://gitlab.example.org/team/mono", "main", "services/billing").orElseThrow().guard())
                .isNotEqualTo(api);
        assertThat(RepositoryIdentity.of("https://gitlab.example.org/team/mono", "main", "Services/API").orElseThrow().guard())
                .as("a directory of a git tree is case-sensitive, unlike the forge's path")
                .isNotEqualTo(api);

        assertThat(RepositoryIdentity.of("https://gitlab.example.org/team/mono", "release/2.x", null).orElseThrow().guard())
                .as("a maintained release line is a target of its own")
                .isNotEqualTo(root);
        assertThat(RepositoryIdentity.of("https://gitlab.example.org/team/mono", "Main", null).orElseThrow().guard())
                .as("git compares branch names exactly")
                .isNotEqualTo(root);
    }

    @Test
    @DisplayName("the guard is 64 characters, the column's width, whatever the parts")
    void theGuardFitsItsColumn() {
        String long255 = "a".repeat(255);
        assertThat(RepositoryIdentity.of("https://gitlab.example.org/" + long255, long255, long255).orElseThrow().guard())
                .hasSize(64)
                .matches("[0-9a-f]{64}");
    }
}
