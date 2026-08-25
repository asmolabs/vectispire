package com.asmolabs.vectispire.core.services;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * The brand identity of this Vectispire deployment.
 *
 * @param name the brand name displayed in headers, reports, and exported documents
 * @param gitlabUrl the upstream GitLab repository URL displayed in the footer
 */
@ConfigurationProperties("vectispire.branding")
public record BrandingProperties(
        @DefaultValue("Vectispire") String name,
        @DefaultValue("https://gitlab.com/asmolabs_be/vectispire") String gitlabUrl) {

    public BrandingProperties {
        name = (name == null || name.isBlank()) ? "Vectispire" : name.trim();
        gitlabUrl = (gitlabUrl == null || gitlabUrl.isBlank())
                ? "https://gitlab.com/asmolabs_be/vectispire"
                : gitlabUrl.trim();
    }
}
