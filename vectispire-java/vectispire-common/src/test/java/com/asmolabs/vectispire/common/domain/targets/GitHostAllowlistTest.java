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
    @DisplayName("an entry that is not a host is refused when the setting is read")
    void aMalformedEntryIsRefused() {
        assertThatThrownBy(() -> GitHostAllowlist.parse("https://gitlab.corp.example"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
