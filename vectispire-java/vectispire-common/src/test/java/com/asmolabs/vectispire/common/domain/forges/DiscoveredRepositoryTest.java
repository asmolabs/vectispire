package com.asmolabs.vectispire.common.domain.forges;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("a discovered repository")
class DiscoveredRepositoryTest {

    private static DiscoveredRepository repository(String path, String branch, Boolean archived) {
        return new DiscoveredRepository("42", path, "acme", false, "api", branch, archived, null, "private",
                Instant.parse("2026-09-01T00:00:00Z"), null, null, "https://git.example.org/" + path + ".git", null, null);
    }

    @Test
    @DisplayName("is compared on what decision 0037 follows: path, default branch, archival, and coming back")
    void changes() {
        assertThat(repository("acme/api", "main", false).changesSince("acme/api", "main", false, false)).isEmpty();
        assertThat(repository("acme/platform/api", "main", false).changesSince("acme/api", "main", false, false))
                .containsExactly("renamed or moved from acme/api");
        assertThat(repository("acme/api", "trunk", false).changesSince("acme/api", "main", false, false))
                .containsExactly("default branch main → trunk");
        assertThat(repository("acme/api", "main", true).changesSince("acme/api", "main", false, false))
                .containsExactly("archived");
        assertThat(repository("acme/api", "main", false).changesSince("acme/api", "main", true, false))
                .containsExactly("unarchived");
        assertThat(repository("acme/api", "main", false).changesSince("acme/api", "main", false, true))
                .containsExactly("seen again after it was gone");
    }

    @Test
    @DisplayName("an unknown is not a change: a branch or an archival flag the forge did not state this time, or before")
    void unknownIsNotAChange() {
        assertThat(repository("acme/api", null, null).changesSince("acme/api", "main", false, false)).isEmpty();
        assertThat(repository("acme/api", "main", false).changesSince("acme/api", null, null, false)).isEmpty();
    }

    @Test
    @DisplayName("a value its column cannot hold is unknown, never cut; a path or a name that long is not kept at all")
    void bounds() {
        DiscoveredRepository outsized = new DiscoveredRepository("42", "acme/api", "acme", false, "api",
                "b".repeat(256), true, null, "private", Instant.parse("+10000-01-01T00:00:00Z"), "L".repeat(101), -1L,
                "https://x/" + "u".repeat(1100), null, null).bounded();
        assertThat(outsized.defaultBranch()).isNull();
        assertThat(outsized.lastActivityAt()).isNull();
        assertThat(outsized.language()).isNull();
        assertThat(outsized.sizeBytes()).isNull();
        assertThat(outsized.httpUrl()).isNull();
        assertThat(outsized.archived()).isTrue();
        assertThat(outsized.unstorable()).isEmpty();

        assertThat(repository("acme/" + "p".repeat(1000), "main", false).unstorable()).isPresent();
        assertThat(new DiscoveredRepository("", "acme/api", "acme", false, "api", null, null, null, null, null, null,
                null, null, null, null).unstorable()).isPresent();
    }
}
