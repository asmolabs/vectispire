package com.asmolabs.vectispire.core.services;

import java.util.Optional;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * What the exported documents say about their producer.
 *
 * @param publicUrl where this deployment is reachable. It goes into SARIF's information URI and
 *     into a VEX document's identifier, so a document handed to somebody else names where it
 *     came from
 * @param vexAuthor a VEX is an assertion about who said what: the default names the tool, and an
 *     organization publishing them outwards will want its own name here
 */
@ConfigurationProperties("vectispire.exports")
public record ExportProperties(
        Optional<String> publicUrl,
        @DefaultValue("Vectispire") String vexAuthor,
        @DefaultValue("1.0.0") String toolVersion) {

    public ExportProperties {
        publicUrl = publicUrl == null ? Optional.empty() : publicUrl.filter(value -> !value.isBlank());
    }
}
