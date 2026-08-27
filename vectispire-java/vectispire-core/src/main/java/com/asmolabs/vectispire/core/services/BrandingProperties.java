package com.asmolabs.vectispire.core.services;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * The brand identity of this Vectispire deployment.
 *
 * @param name the brand name displayed in headers, reports, and exported documents
 * @param gitlabUrl the upstream repository URL displayed in the footer — GitHub since the 2026-08-27
 *                  move; the field name predates it and is part of the public branding response
 */
@ConfigurationProperties("vectispire.branding")
public record BrandingProperties(
        @DefaultValue("Vectispire") String name,
        @DefaultValue("https://github.com/asmolabs/vectispire") String gitlabUrl) {

    public BrandingProperties {
        name = (name == null || name.isBlank()) ? "Vectispire" : name.trim();
        gitlabUrl = (gitlabUrl == null || gitlabUrl.isBlank())
                ? "https://github.com/asmolabs/vectispire"
                : gitlabUrl.trim();
    }
}
