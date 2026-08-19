package com.asmolabs.zanshin.common.domain.exports;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Map;

/**
 * An OpenVEX document, as records rather than nested maps.
 *
 * <p>The document <em>is</em> the type. The NestJS version assembled
 * {@code Record<string, unknown>} and relied on the reader to know which keys are
 * conditional; here an absent field is an absent {@code null} on a record with
 * {@link JsonInclude.Include#NON_NULL}, and the specification's shape is readable without
 * running anything.
 *
 * <p>VEX is the reason triage decisions are stored in the standard's vocabulary rather than
 * as free text: this is a serialization, not a translation. Every field a statement needs is
 * already on the issue — nothing here infers or invents, which is what makes the document
 * trustworthy enough to hand to a customer or an auditor.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record OpenVexDocument(
        @JsonProperty("@context") String context,
        @JsonProperty("@id") String id,
        String author,
        String timestamp,
        int version,
        String tooling,
        List<Statement> statements) {

    public static final String CONTEXT = "https://openvex.dev/ns/v0.2.0";

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Statement(
            Vulnerability vulnerability,
            List<Product> products,
            String status,
            /* Required by the specification for `not_affected`, absent otherwise. */
            String justification,
            @JsonProperty("impact_statement") String impactStatement,
            @JsonProperty("action_statement") String actionStatement,
            String timestamp) {}

    public record Vulnerability(String name) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Product(@JsonProperty("@id") String id, Map<String, String> identifiers) {}
}
