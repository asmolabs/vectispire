package com.asmolabs.vectispire.common.domain.targets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("the git host allowlist")
class GitHostAllowlistTest {

    @Test
    @DisplayName("empty allows every host, which is the default")
    void emptyAllowsEverything() {
        GitHostAllowlist none = GitHostAllowlist.parse("  ");
        assertThat(none.restricts()).isFalse();
        assertThat(none.permits("https://anywhere.example/x.git")).isTrue();
    }

    @Test
    @DisplayName("listed, only those hosts — exact names and subdomains of a *. entry")
    void listedHostsOnly() {
        GitHostAllowlist list = GitHostAllowlist.parse("GitLab.Corp.Example, *.forge.example");

        assertThat(list.permits("https://gitlab.corp.example/team/a.git")).isTrue();
        assertThat(list.permits("git@gitlab.corp.example:team/a.git")).isTrue();
        assertThat(list.permits("ssh://git@gitlab.corp.example:2222/team/a.git")).isTrue();
        assertThat(list.permits("https://eu.forge.example/a.git")).isTrue();

        assertThat(list.permits("https://forge.example/a.git")).as("the suffix entry is not its own apex").isFalse();
        assertThat(list.permits("https://gitlab.corp.example.evil.net/a.git")).isFalse();
        assertThat(list.permits("https://evilforge.example/a.git")).isFalse();
        assertThat(list.permits("https://github.com/a/b.git")).isFalse();
        assertThat(list.refusal("https://github.com/a/b.git")).contains("github.com").contains("gitlab.corp.example");
    }

    @Test
    @DisplayName("a URL naming a listed host to one parser and another host to the clone is refused")
    void anAmbiguousHostIsNotPermitted() {
        // java.net.URI reads the listed host; JGit, which clones, reads the other one.
        GitHostAllowlist list = GitHostAllowlist.parse("gitlab.corp.example");

        assertThat(list.permits("https://gitlab.corp.example#@evil.example/a.git")).isFalse();
        assertThat(list.permits("https://gitlab.corp.example?@evil.example/a.git")).isFalse();
    }

    @Test
    @DisplayName("an entry that is not a host is refused when the setting is read")
    void aMalformedEntryIsRefused() {
        assertThatThrownBy(() -> GitHostAllowlist.parse("https://gitlab.corp.example"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("a clone's port is the one written, or its transport's")
    void aCloneReachesItsTransportsPort() {
        assertThat(RepositoryUrl.port("https://forge.example/x.git")).hasValue(443);
        assertThat(RepositoryUrl.port("http://forge.example/x.git")).hasValue(80);
        assertThat(RepositoryUrl.port("ssh://git@forge.example/x.git")).hasValue(22);
        assertThat(RepositoryUrl.port("git@forge.example:group/x.git")).hasValue(22);
        assertThat(RepositoryUrl.port("git://forge.example/x.git")).hasValue(9418);
        assertThat(RepositoryUrl.port("ssh://git@forge.example:2222/x.git")).hasValue(2222);
    }

    @Test
    @DisplayName("a reserved endpoint is refused whether the list is empty or names its host")
    void aReservedEndpointIsNeverCloned() {
        GitHostAllowlist.Reserved database = (host, port) -> host.equals("db.internal") && port == 3306
                ? java.util.Optional.of("db.internal:3306 is the database")
                : java.util.Optional.empty();

        for (GitHostAllowlist hosts : new GitHostAllowlist[] {
            GitHostAllowlist.parse("").refusing(database), GitHostAllowlist.parse("db.internal").refusing(database)
        }) {
            assertThat(hosts.permits("http://db.internal:3306/x.git")).isFalse();
            assertThat(hosts.refusal("http://db.internal:3306/x.git")).isEqualTo("db.internal:3306 is the database");
        }
        assertThat(GitHostAllowlist.parse("").refusing(database).permits("https://db.internal/x.git")).isTrue();
    }
}
