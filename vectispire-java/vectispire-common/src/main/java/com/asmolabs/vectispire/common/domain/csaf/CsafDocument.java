package com.asmolabs.vectispire.common.domain.csaf;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * An OASIS CSAF 2.0 (Common Security Advisory Framework) JSON document for VEX advisories.
 * Standard: OASIS CSAF v2.0 / BSI / CISA specification.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CsafDocument(
        @JsonProperty("document") DocumentMetadata document,
        @JsonProperty("product_tree") ProductTree productTree,
        @JsonProperty("vulnerabilities") List<CsafVulnerability> vulnerabilities) {

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record DocumentMetadata(
            @JsonProperty("category") String category,
            @JsonProperty("csaf_version") String csafVersion,
            @JsonProperty("title") String title,
            @JsonProperty("publisher") Publisher publisher,
            @JsonProperty("tracking") Tracking tracking) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Publisher(
            @JsonProperty("category") String category,
            @JsonProperty("name") String name,
            @JsonProperty("namespace") String namespace) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Tracking(
            @JsonProperty("id") String id,
            @JsonProperty("current_release_date") Instant currentReleaseDate,
            @JsonProperty("initial_release_date") Instant initialReleaseDate,
            @JsonProperty("status") String status,
            @JsonProperty("version") String version) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ProductTree(
            @JsonProperty("full_product_names") List<FullProductName> fullProductNames) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record FullProductName(
            @JsonProperty("product_id") String productId,
            @JsonProperty("name") String name,
            @JsonProperty("product_identification_helper") Map<String, String> productIdentificationHelper) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record CsafVulnerability(
            @JsonProperty("cve") String cve,
            @JsonProperty("title") String title,
            @JsonProperty("product_status") ProductStatus productStatus,
            @JsonProperty("threats") List<Threat> threats,
            @JsonProperty("notes") List<Note> notes) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ProductStatus(
            @JsonProperty("known_not_affected") List<String> knownNotAffected,
            @JsonProperty("known_affected") List<String> knownAffected,
            @JsonProperty("fixed") List<String> fixed,
            @JsonProperty("under_investigation") List<String> underInvestigation) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Threat(
            @JsonProperty("category") String category,
            @JsonProperty("details") String details,
            @JsonProperty("product_ids") List<String> productIds) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Note(
            @JsonProperty("category") String category,
            @JsonProperty("title") String title,
            @JsonProperty("text") String text) {}
}
