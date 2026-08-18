package com.asmolabs.zanshin.core.services;

import java.util.Optional;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * What the control plane decides about scanning, as opposed to what an executor decides.
 *
 * @param imagePlatform the variant of an image to pull, {@code linux/amd64} and the like. Empty
 *     lets the daemon choose, which means the host's architecture — so an arm64 development
 *     machine would audit a variant nobody deploys. It lives here rather than on the agent
 *     because it is a decision about <em>what we want scanned</em>, not about the machine that
 *     runs the scan
 */
@ConfigurationProperties("zanshin.scanning")
public record ScanningProperties(Optional<String> imagePlatform) {

    public ScanningProperties {
        imagePlatform = imagePlatform == null ? Optional.empty() : imagePlatform.filter(value -> !value.isBlank());
    }
}
