package com.asmolabs.vectispire.common.domain.net;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("reading a Link header for the next page")
class LinkHeaderTest {

    @Test
    @DisplayName("GitHub's header: the next page among first, prev and last")
    void github() {
        String header = "<https://api.github.com/organizations/1/repos?type=all&per_page=100&page=1>; rel=\"prev\", "
                + "<https://api.github.com/organizations/1/repos?type=all&per_page=100&page=3>; rel=\"next\", "
                + "<https://api.github.com/organizations/1/repos?type=all&per_page=100&page=9>; rel=\"last\"";

        assertThat(LinkHeader.target(header, "next"))
                .contains("https://api.github.com/organizations/1/repos?type=all&per_page=100&page=3");
        assertThat(LinkHeader.target(header, "last")).hasValueSatisfying(last -> assertThat(last).endsWith("page=9"));
    }

    @Test
    @DisplayName("a GitLab keyset cursor whose URL carries commas and semicolons is read whole")
    void commasInsideTheTarget() {
        String header = "<https://gitlab.example.org/api/v4/projects?id_after=42&cursor=a,b;c&per_page=100>; rel=\"next\"";

        assertThat(LinkHeader.target(header, "next"))
                .contains("https://gitlab.example.org/api/v4/projects?id_after=42&cursor=a,b;c&per_page=100");
    }

    @Test
    @DisplayName("rel unquoted, in another case, or naming several types")
    void relationForms() {
        assertThat(LinkHeader.target("</p2>; rel=next, </p9>; rel=last", "next")).contains("/p2");
        assertThat(LinkHeader.target("</p2>; REL=\"Next\"", "next")).contains("/p2");
        assertThat(LinkHeader.target("</p2>; rel=\"prefetch next\"", "next")).contains("/p2");
        assertThat(LinkHeader.target("</p9>; rel=\"last\", </p2>; title=\"x, y\"; rel=\"next\"", "next")).contains("/p2");
    }

    @Test
    @DisplayName("the last page names no next: empty, and so is a header nobody can read")
    void noNext() {
        assertThat(LinkHeader.target("<https://x/p1>; rel=\"first\", <https://x/p9>; rel=\"last\"", "next")).isEmpty();
        assertThat(LinkHeader.target("<https://x/p1>; rel=\"nextish\"", "next")).isEmpty();
        assertThat(LinkHeader.target(null, "next")).isEmpty();
        assertThat(LinkHeader.target("", "next")).isEmpty();
        assertThat(LinkHeader.target("<https://x/p2; rel=\"next\"", "next")).isEmpty();
    }
}
