package com.asmolabs.zanshin.common.domain.cyclonedx;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;
import java.util.List;

/**
 * Pure domain model for CycloneDX 1.5 / 1.6 Software Bill of Materials (SBOM) with
 * native Vulnerability Exploitability eXchange (VEX) formulation (BOM-linked VEX).
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CycloneDxDocument(
        String bomFormat,
        String specVersion,
        String serialNumber,
        int version,
        Metadata metadata,
        List<Component> components,
        List<Vulnerability> vulnerabilities) {

    public static final String BOM_FORMAT = "CycloneDX";
    public static final String SPEC_VERSION = "1.5";

    public record Metadata(
            Instant timestamp,
            List<Tool> tools,
            Component component) {}

    public record Tool(
            String vendor,
            String name,
            String version) {}

    public record Component(
            @JsonProperty("bom-ref") String bomRef,
            String type,
            String group,
            String name,
            String version,
            String purl,
            String scope) {}

    public record Vulnerability(
            @JsonProperty("bom-ref") String bomRef,
            String id,
            Source source,
            List<Rating> ratings,
            String description,
            String detail,
            String recommendation,
            Analysis analysis,
            List<Affects> affects) {}

    public record Source(
            String name,
            String url) {}

    public record Rating(
            Source source,
            Double score,
            String severity,
            String method,
            String vector) {}

    public record Analysis(
            String state,
            String justification,
            String detail,
            List<String> responses) {}

    public record Affects(
            String ref) {}
}
