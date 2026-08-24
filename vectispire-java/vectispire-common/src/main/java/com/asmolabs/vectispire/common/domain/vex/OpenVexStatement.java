package com.asmolabs.vectispire.common.domain.vex;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Map;

/**
 * An OpenVEX statement asserting vulnerability exploitability for given products.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record OpenVexStatement(
        @JsonProperty("vulnerability") Map<String, String> vulnerability,
        @JsonProperty("products") List<String> products,
        @JsonProperty("status") VexStatus status,
        @JsonProperty("justification") VexJustification justification,
        @JsonProperty("impact_statement") String impactStatement,
        @JsonProperty("action_statement") String actionStatement,
        @JsonProperty("status_notes") String statusNotes) {

    public static OpenVexStatement notAffected(String cveId, String purl, VexJustification justification, String impactStatement) {
        return new OpenVexStatement(
                Map.of("name", cveId),
                List.of(purl != null && !purl.isBlank() ? purl : "pkg:generic/" + cveId),
                VexStatus.NOT_AFFECTED,
                justification,
                impactStatement,
                null,
                null);
    }

    public static OpenVexStatement affected(String cveId, String purl, String actionStatement) {
        return new OpenVexStatement(
                Map.of("name", cveId),
                List.of(purl != null && !purl.isBlank() ? purl : "pkg:generic/" + cveId),
                VexStatus.AFFECTED,
                null,
                null,
                actionStatement,
                null);
    }

    public static OpenVexStatement fixed(String cveId, String purl, String fixNotes) {
        return new OpenVexStatement(
                Map.of("name", cveId),
                List.of(purl != null && !purl.isBlank() ? purl : "pkg:generic/" + cveId),
                VexStatus.FIXED,
                null,
                null,
                null,
                fixNotes);
    }
}
