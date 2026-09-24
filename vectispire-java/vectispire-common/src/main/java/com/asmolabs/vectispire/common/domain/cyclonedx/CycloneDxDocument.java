package com.asmolabs.vectispire.common.domain.cyclonedx;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;
import java.util.List;

/**
 * Pure domain model for CycloneDX 1.5 / 1.6 Software Bill of Materials (SBOM) with
 * native Vulnerability Exploitability eXchange (VEX) formulation (BOM-linked VEX).
 */
// **On every nested record too.** The annotation on this record reaches its own properties only;
// the components, tools and vulnerabilities inside it serialised their nulls, so the aggregate's
// root component went out with `"purl": null` and `"scope": null` — values the CycloneDX schema does
// not accept, where an absent field is valid.
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

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Metadata(
            Instant timestamp,
            List<Tool> tools,
            Component component) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Tool(
            String vendor,
            String name,
            String version) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Component(
            @JsonProperty("bom-ref") String bomRef,
            String type,
            String group,
            String name,
            String version,
            String purl,
            String scope) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
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

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Source(
            String name,
            String url) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Rating(
            Source source,
            Double score,
            String severity,
            String method,
            String vector) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Analysis(
            String state,
            String justification,
            String detail,
            List<String> responses) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Affects(
            String ref) {}
}
