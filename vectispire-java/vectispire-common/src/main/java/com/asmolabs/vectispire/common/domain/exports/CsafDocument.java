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
        List<CsafVulnerability> vulnerabilities) {

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

    /**
     * @param revisionHistory <b>required by the schema, and it was missing.</b> CSAF 2.0 lists six
     *     mandatory tracking properties and this record carried five; a consumer validating
     *     against the published schema rejects the document outright. Nothing here noticed,
     *     because nothing validated: the generator's tests asserted the fields the generator
     *     writes, which can only fail if the generator changes and never if it was wrong from the
     *     start
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Tracking(
            @JsonProperty("current_release_date") String currentReleaseDate,
            @JsonProperty("initial_release_date") String initialReleaseDate,
            String id,
            String status,
            String version,
            @JsonProperty("revision_history") List<Revision> revisionHistory,
            Generator generator) {}

    /**
     * One entry of the revision history.
     *
     * <p>A generated advisory has one revision by construction — it is rebuilt from current data
     * rather than amended — so the history has a single entry saying when this rendering was
     * produced. That is honest and it is what the schema asks for; inventing a longer history for
     * a document that has none would be worse than the omission it replaces.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Revision(String number, String date, String summary) {}

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
    public record CsafVulnerability(
            String cve,
            String title,
            List<Note> notes,
            @JsonProperty("product_status") ProductStatus productStatus,
            List<Threat> threats,
            List<Flag> flags,
            List<Remediation> remediations,
            List<Score> scores) {}

    /**
     * What the vulnerability does to the named products.
     *
     * <p>Carried over from the model this one replaced, which had it where this one did not. A
     * consolidation that quietly dropped a populated field would have been a regression wearing
     * the clothes of a clean-up.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Threat(
            String category,
            String details,
            @JsonProperty("product_ids") List<String> productIds) {}

    /**
     * <p><b>Affected comes first here, and did not in the model this replaced.</b> The two records
     * took their four lists in a different order, so a port that moved arguments across by
     * position would have published every affected product as cleared and every cleared product as
     * affected — in a signed document, over a machine-readable field whose whole purpose is to be
     * believed without reading.
     */
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
