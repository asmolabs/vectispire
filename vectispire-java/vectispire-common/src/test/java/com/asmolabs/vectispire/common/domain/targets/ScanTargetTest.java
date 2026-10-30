package com.asmolabs.vectispire.common.domain.targets;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("a scan target, from its names")
class ScanTargetTest {

    @Test
    @DisplayName("a kind names a target exactly, and any other spelling names none")
    void aKindIsExact() {
        assertThat(ScanTarget.of("repository", 7)).contains(new ScanTarget.Repository(7));
        assertThat(ScanTarget.of("container", 3)).contains(new ScanTarget.Container(3));
        // Normalised where it enters, never guessed here: a grant or a key spelt otherwise grants nothing.
        assertThat(ScanTarget.of("Repository", 7)).isEmpty();
        assertThat(ScanTarget.of("project", 7)).isEmpty();
        assertThat(ScanTarget.of(null, 7)).isEmpty();
    }

    @Test
    @DisplayName("the kind read back is the kind it was named by")
    void theKindRoundTrips() {
        assertThat(new ScanTarget.Repository(1).kind()).isEqualTo(ScanTarget.KIND_REPOSITORY);
        assertThat(new ScanTarget.Container(1).kind()).isEqualTo(ScanTarget.KIND_CONTAINER);
    }

    @Test
    @DisplayName("a row's columns name the repository first, then the container, else nothing")
    void columnsPreferTheRepository() {
        assertThat(ScanTarget.ofColumns(7L, null)).isEqualTo(new ScanTarget.Repository(7));
        assertThat(ScanTarget.ofColumns(null, 3L)).isEqualTo(new ScanTarget.Container(3));
        // Repository zero is a repository: the test is on null, never on truthiness.
        assertThat(ScanTarget.ofColumns(0L, 3L)).isEqualTo(new ScanTarget.Repository(0));
        assertThat(ScanTarget.ofColumns(null, null)).isNull();
    }

    @Test
    @DisplayName("a fingerprint key reads back as the target that wrote it, and nothing else does")
    void theFingerprintKeyRoundTrips() {
        ScanTarget repository = new ScanTarget.Repository(7);
        ScanTarget container = new ScanTarget.Container(3);

        assertThat(ScanTarget.fromFingerprintKey(repository.fingerprintKey())).contains(repository);
        assertThat(ScanTarget.fromFingerprintKey(container.fingerprintKey())).contains(container);
        assertThat(ScanTarget.fromFingerprintKey("repository:7")).as("the kind is not the key's spelling").isEmpty();
        assertThat(ScanTarget.fromFingerprintKey("repo:seven")).isEmpty();
        assertThat(ScanTarget.fromFingerprintKey("repo")).isEmpty();
    }
}
