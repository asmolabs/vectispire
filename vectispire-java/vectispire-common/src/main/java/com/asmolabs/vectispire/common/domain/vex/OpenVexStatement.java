package com.asmolabs.vectispire.common.domain.vex;

import com.asmolabs.vectispire.common.domain.issues.VexJustification;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * An OpenVEX statement asserting vulnerability exploitability for given products.
 *
 * <p><b>{@code products} carries objects, which is what v0.2.0 says and what this got wrong.</b>
 * The specification's own example reads {@code [{"@id": "pkg:apk/wolfi/git@2.39.0-r1"}]}; this
 * record modelled a list of bare strings while the document above it declared
 * {@code @context: openvex.dev/ns/v0.2.0}. Two consequences, and both were silent: every
 * conformant document from anybody else was refused on ingest, and the document Vectispire signs
 * into an evidence bundle did not satisfy the version it announced.
 *
 * <p><b>The justification is the triage service's own enumeration, which is the second thing this
 * got wrong.</b> A local copy lived beside this record carrying {@code inline_mitigations_exist};
 * the specification's label is {@code inline_mitigations_already_exist}. Two enumerations of one
 * controlled vocabulary is how one of them comes to be wrong without anybody noticing — the value
 * left the building on every signed advisory, and the only reader who would have complained is a
 * downstream consumer nobody hears from.
 *
 * <p>{@code timestamp} is per-statement, as the specification allows: when <em>this</em> assertion
 * was made, which is not when the document was assembled. A register of decisions that dates them
 * all to the moment of export loses the only thing an assessor wanted from it.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record OpenVexStatement(
        @JsonProperty("vulnerability") Map<String, String> vulnerability,
        @JsonProperty("products") List<Product> products,
        @JsonProperty("status") VexStatus status,
        @JsonProperty("justification") VexJustification justification,
        @JsonProperty("impact_statement") String impactStatement,
        @JsonProperty("action_statement") String actionStatement,
        @JsonProperty("status_notes") String statusNotes,
        @JsonProperty("timestamp") Instant timestamp) {

    /**
     * A product a statement is about.
     *
     * <p><b>It reads the older bare-string form too, and that asymmetry is deliberate.</b>
     * Vectispire emitted strings for a long time; documents carrying them are sitting in
     * customers' evidence folders, and a reader that now refused them would reject the files this
     * product taught people to keep. So: objects out, either form in.
     *
     * @param id the product identifier — a purl, a CPE, whatever names the thing
     * @param identifiers further names for the same product, keyed by scheme
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Product(
            @JsonProperty("@id") String id,
            @JsonProperty("identifiers") Map<String, String> identifiers) {

        /**
         * The older bare-string form, delegating.
         *
         * <p>Declared {@code DELEGATING} rather than left to Jackson: the canonical record
         * constructor is already the properties-based creator, and two creators whose mode has to
         * be guessed is a conflict Jackson refuses outright — which turns every response carrying
         * this record into a 400.
         */
        @JsonCreator(mode = JsonCreator.Mode.DELEGATING)
        public static Product of(String id) {
            return new Product(id, null);
        }
    }

    private static List<Product> productsOf(String cveId, String purl) {
        return List.of(Product.of(purl != null && !purl.isBlank() ? purl : "pkg:generic/" + cveId));
    }

    public static OpenVexStatement notAffected(String cveId, String purl, VexJustification justification, String impactStatement) {
        return new OpenVexStatement(
                Map.of("name", cveId),
                productsOf(cveId, purl),
                VexStatus.NOT_AFFECTED,
                justification,
                impactStatement,
                null,
                null,
                null);
    }

    public static OpenVexStatement affected(String cveId, String purl, String actionStatement) {
        return new OpenVexStatement(
                Map.of("name", cveId),
                productsOf(cveId, purl),
                VexStatus.AFFECTED,
                null,
                null,
                actionStatement,
                null,
                null);
    }

    public static OpenVexStatement fixed(String cveId, String purl, String fixNotes) {
        return new OpenVexStatement(
                Map.of("name", cveId),
                productsOf(cveId, purl),
                VexStatus.FIXED,
                null,
                null,
                null,
                fixNotes,
                null);
    }
}
