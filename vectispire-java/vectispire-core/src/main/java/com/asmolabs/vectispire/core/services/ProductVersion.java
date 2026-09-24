package com.asmolabs.vectispire.core.services;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.info.BuildProperties;
import org.springframework.stereotype.Component;

/**
 * The version every document Vectispire produces states about itself — SARIF, CSAF, CycloneDX and
 * the in-toto statement — from one place.
 *
 * <p><b>Why one place.</b> The version was a literal in four files, kept in step by a test, and the
 * signed documents read it from two different sources: SARIF and CSAF from configuration, whose
 * default was {@code 1.0.0} in code and {@code 0.9.0} in YAML; CycloneDX and the attestation from
 * the build. Setting {@code VECTISPIRE_VERSION} changed half of them. Every release meant editing
 * the literals, and forgetting one put a version nobody could obtain inside a document somebody
 * verifies.
 *
 * <p>The build's own metadata is the source; {@code vectispire.exports.tool-version} overrides it
 * for a vendor rebuild that ships under its own version. Neither present means {@code null}, and
 * every format leaves the field out rather than stating a guess.
 */
@Component
public class ProductVersion {

    private final String version;

    public ProductVersion(ExportProperties exports, ObjectProvider<BuildProperties> build) {
        String configured = exports.toolVersion();
        BuildProperties properties = build.getIfAvailable();
        this.version = configured != null && !configured.isBlank()
                ? configured.trim()
                : properties == null ? null : properties.getVersion();
    }

    /** The version, or {@code null} when neither the build nor the configuration states one. */
    public String get() {
        return version;
    }
}
