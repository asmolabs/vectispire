package com.asmolabs.vectispire.common.domain.plugins;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("a plugin image, relocated to an internal registry")
class ImageDigestTest {

    private static final String DIGEST = "sha256:" + "c".repeat(64);

    @Test
    @DisplayName("without a mirror the reference is unchanged")
    void noMirror() {
        assertThat(ImageDigest.relocate("ghcr.io/acme/lint@" + DIGEST, "")).isEqualTo("ghcr.io/acme/lint@" + DIGEST);
        assertThat(ImageDigest.relocate("ghcr.io/acme/lint@" + DIGEST, null)).isEqualTo("ghcr.io/acme/lint@" + DIGEST);
    }

    @Test
    @DisplayName("the registry host is swapped and the path and the digest kept, so the mirror cannot substitute")
    void relocated() {
        assertThat(ImageDigest.relocate("ghcr.io/acme/lint@" + DIGEST, "mirror.internal:5000/cache/"))
                .isEqualTo("mirror.internal:5000/cache/acme/lint@" + DIGEST);
        assertThat(ImageDigest.relocate("localhost:5000/acme/lint@" + DIGEST, "mirror.internal"))
                .isEqualTo("mirror.internal/acme/lint@" + DIGEST);
    }

    @Test
    @DisplayName("an image with no registry is Docker Hub's, and a bare name is in Hub's library")
    void dockerHub() {
        assertThat(ImageDigest.relocate("acme/lint@" + DIGEST, "mirror.internal"))
                .isEqualTo("mirror.internal/acme/lint@" + DIGEST);
        assertThat(ImageDigest.relocate("busybox@" + DIGEST, "mirror.internal"))
                .isEqualTo("mirror.internal/library/busybox@" + DIGEST);
    }

    @Test
    @DisplayName("a mirror is a host, a port and a path: a scheme or a credential is refused")
    void mirrorShape() {
        assertThatThrownBy(() -> ImageDigest.requireMirror("https://mirror.internal"))
                .isInstanceOf(InvalidPluginException.class);
        assertThatThrownBy(() -> ImageDigest.requireMirror("user:pass@mirror.internal"))
                .isInstanceOf(InvalidPluginException.class);
        assertThatThrownBy(() -> ImageDigest.requireMirror("mirror internal")).isInstanceOf(InvalidPluginException.class);
    }
}
