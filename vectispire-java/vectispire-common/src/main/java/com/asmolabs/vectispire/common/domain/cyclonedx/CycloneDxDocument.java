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
        List<Vulnerability> vulnerabilities,
        List<Composition> compositions) {

    public static final String BOM_FORMAT = "CycloneDX";
    public static final String SPEC_VERSION = "1.5";

    /** A document that states nothing of its own completeness: the per-scan and the fleet's. */
    public CycloneDxDocument(
            String bomFormat,
            String specVersion,
            String serialNumber,
            int version,
            Metadata metadata,
            List<Component> components,
            List<Vulnerability> vulnerabilities) {
        this(bomFormat, specVersion, serialNumber, version, metadata, components, vulnerabilities, null);
    }

    /**
     * @param properties name-value pairs in a namespace of Vectispire's ({@code vectispire:…}), which
     *     CycloneDX 1.5 allows on the metadata and on a component — how a project's document says which
     *     of its targets carry a component and which were not read
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Metadata(
            Instant timestamp,
            List<Tool> tools,
            Component component,
            List<Property> properties) {

        public Metadata(Instant timestamp, List<Tool> tools, Component component) {
            this(timestamp, tools, component, null);
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Property(String name, String value) {}

    /**
     * What the document claims of its own completeness — CycloneDX 1.5's {@code compositions}, whose
     * {@code aggregate} is {@code complete}, {@code incomplete} or {@code unknown}, among others. A
     * consumer reading a component list without it cannot tell "this is all" from "this is what was
     * seen"; a project's document states which (decision 0007).
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Composition(String aggregate, List<String> assemblies) {}

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
            String scope,
            List<Property> properties) {

        public Component(String bomRef, String type, String group, String name, String version, String purl, String scope) {
            this(bomRef, type, group, name, version, purl, scope, null);
        }
    }

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
