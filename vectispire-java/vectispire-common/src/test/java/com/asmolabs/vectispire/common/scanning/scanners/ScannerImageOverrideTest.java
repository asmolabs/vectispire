package com.asmolabs.vectispire.common.scanning.scanners;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Naming a scanner image, which the class documented long before anything implemented it.
 *
 * <p>{@code ScannerImages} said "each image stays overridable, because an operator running an
 * internal mirror needs that" while both construction sites passed {@link ScannerImages#PINNED}
 * straight through — so an air-gapped estate could not run Vectispire without editing source.
 *
 * <p>This is what remains of the suite that used to cover a second secrets engine. Decision 0015
 * removed that seam; the override it was configured through is the part that turned out to
 * matter, and it is also how somebody replaces the secrets scanner with a fork or a mirror.
 */
@DisplayName("scanner image overrides")
class ScannerImageOverrideTest {

    @Test
    @DisplayName("a blank override keeps the pinned digest, because unset config arrives as \"\"")
    void blankOverridesKeepThePinnedDigests() {
        // An unset environment variable rendered into YAML is the empty string, not absence.
        // Treating that as a deliberate choice would replace a reviewed digest with nothing.
        assertThat(ScannerImages.PINNED.withOverrides("", "  ", null, "", null))
                .isEqualTo(ScannerImages.PINNED);
    }

    @Test
    @DisplayName("an internal registry can be named, one image at a time")
    void imagesAreOverridable() {
        ScannerImages mirrored = ScannerImages.PINNED.withOverrides(
                "registry.internal/syft@sha256:1", null, null, null, null);

        assertThat(mirrored.syft()).isEqualTo("registry.internal/syft@sha256:1");
        assertThat(mirrored.grype())
                .as("naming one image must not disturb the others")
                .isEqualTo(ScannerImages.PINNED.grype());
    }

    @Test
    @DisplayName("the secrets scanner is replaced by naming it, which is what the seam was for")
    void theSecretsScannerCanBeReplaced() {
        // The removed second-engine seam only ever accepted gitleaks-compatible images. This
        // covers the same ground with one image and no second pass — see decision 0015.
        ScannerImages forked = ScannerImages.PINNED.withOverrides(
                null, null, "registry.internal/gitleaks@sha256:2", null, null);

        assertThat(forked.gitleaks()).isEqualTo("registry.internal/gitleaks@sha256:2");
    }
}
