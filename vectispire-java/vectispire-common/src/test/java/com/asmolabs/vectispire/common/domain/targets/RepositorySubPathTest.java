package com.asmolabs.vectispire.common.domain.targets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@DisplayName("a repository sub-path")
class RepositorySubPathTest {

    @ParameterizedTest(name = "refuses \"{0}\"")
    @ValueSource(strings = {"/", "/etc", "..", "../..", "a/../../b", "./a", "a//b", "a\\b", "C:/x", "a/./b", "a b"})
    void refusesAnythingThatIsNotADirectoryOfTheRepository(String subPath) {
        // "/" replaced the clone with the host's root in Path.resolve, and "../.." reached the
        // other scans' clones in the temporary directory.
        assertThat(RepositorySubPath.validate(subPath)).isPresent();
        assertThatThrownBy(() -> RepositorySubPath.normalize(subPath)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("accepts a relative directory, and stores it without its trailing slash")
    void acceptsAndNormalizes() {
        assertThat(RepositorySubPath.normalize("services/billing/")).isEqualTo("services/billing");
        assertThat(RepositorySubPath.normalize(" apps/web-2.0 ")).isEqualTo("apps/web-2.0");
        assertThat(RepositorySubPath.normalize("")).isEmpty();
        assertThat(RepositorySubPath.normalize(null)).isEmpty();
    }
}
