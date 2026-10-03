package com.asmolabs.vectispire.common.domain.forges;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Optional;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class ForgeVersionTest {

    @ParameterizedTest(name = "{0} {1} too old: {2}")
    @CsvSource({
        "GITLAB_SELF_MANAGED, 15.11.13-ee, true",
        "GITLAB_SELF_MANAGED, 16.0.0, false",
        "GITLAB_SELF_MANAGED, 17.4.1-ee, false",
        "GITHUB_ENTERPRISE_SERVER, 3.11.9, true",
        "GITHUB_ENTERPRISE_SERVER, 3.12.0, false",
        "GITHUB_ENTERPRISE_SERVER, 2.22.1, true",
        "GITHUB_ENTERPRISE_SERVER, 4.0.0, false",
    })
    void comparesWithTheOldestSupported(ForgeEdition edition, String version, boolean tooOld) {
        assertThat(ForgeVersion.tooOld(edition, version)).contains(tooOld);
    }

    @ParameterizedTest(name = "\"{0}\" proves nothing")
    @CsvSource({"''", "unknown", "v"})
    void anUnreadableVersionIsUnknown(String version) {
        assertThat(ForgeVersion.tooOld(ForgeEdition.GITLAB_SELF_MANAGED, version)).isEqualTo(Optional.empty());
    }
}
