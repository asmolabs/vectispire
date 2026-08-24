package com.asmolabs.vectispire.common.domain.exports;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Map;

/**
 * OASIS CSAF 2.0 (Common Security Advisory Framework) JSON document for VEX profile.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CsafDocument(
        Document document,
        @JsonProperty("product_tree") ProductTree productTree,
        List<Vulnerability> vulnerabilities) {

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Document(
            String category,
            @JsonProperty("csaf_version") String csafVersion,
            String title,
            Publisher publisher,
            Tracking tracking,
            List<Note> notes) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Publisher(
            String category,
            String name,
            String namespace) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Tracking(
            @JsonProperty("current_release_date") String currentReleaseDate,
            @JsonProperty("initial_release_date") String initialReleaseDate,
            String id,
            String status,
            String version,
            Generator generator) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Generator(
            Engine engine,
            String date) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Engine(
            String name,
            String version) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Note(
            String category,
            String title,
            String text) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ProductTree(
            @JsonProperty("full_product_names") List<FullProductName> fullProductNames) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record FullProductName(
            String name,
            @JsonProperty("product_id") String productId,
            @JsonProperty("product_identification_helper") ProductIdentificationHelper productIdentificationHelper) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ProductIdentificationHelper(
            String purl,
            String cpe) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Vulnerability(
            String cve,
            String title,
            List<Note> notes,
            @JsonProperty("product_status") ProductStatus productStatus,
            List<Flag> flags,
            List<Remediation> remediations,
            List<Score> scores) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ProductStatus(
            @JsonProperty("known_affected") List<String> knownAffected,
            @JsonProperty("known_not_affected") List<String> knownNotAffected,
            List<String> fixed,
            @JsonProperty("under_investigation") List<String> underInvestigation) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Flag(
            String label,
            @JsonProperty("product_ids") List<String> productIds,
            String date) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Remediation(
            String category,
            String details,
            @JsonProperty("product_ids") List<String> productIds) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Score(
            @JsonProperty("cvss_v3") Map<String, Object> cvssV3) {}
}
