package com.asmolabs.vectispire.common.domain.exports;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Whether a document calling itself CSAF 2.0 satisfies CSAF 2.0.
 *
 * <h2>Why an assertion about required fields and not about content</h2>
 *
 * <p><b>A consumer validating against the published schema is the first reader who will not be
 * polite about it.</b> CSAF 2.0's schema names six required properties under {@code tracking} —
 * {@code current_release_date}, {@code id}, {@code initial_release_date},
 * {@code revision_history}, {@code status}, {@code version} — and this product emitted five of
 * them, from two separate models, on two routes, one of them signed into an evidence bundle.
 *
 * <p>Nothing noticed because nothing ever validated. The generator's own tests asserted the
 * fields the generator writes, which is a tautology: they could only ever fail if the generator
 * changed, never if it was wrong from the start.
 *
 * <p>So the list below is copied from the schema rather than from the code, and that is the whole
 * point of the file. It is the one assertion a test can make that the implementation did not get
 * a vote in.
 */
@DisplayName("a CSAF 2.0 document")
class CsafConformanceTest {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    /** From the CSAF 2.0 JSON schema, {@code /document/tracking}. */
    private static final List<String> TRACKING_REQUIRED = List.of(
            "current_release_date", "id", "initial_release_date", "revision_history", "status", "version");

    /** From the CSAF 2.0 JSON schema, {@code /document}. */
    private static final List<String> DOCUMENT_REQUIRED =
            List.of("category", "csaf_version", "publisher", "title", "tracking");

    @Test
    @DisplayName("carries every property its schema makes mandatory")
    void carriesTheMandatoryProperties() throws Exception {
        JsonNode document = emit().get("document");

        assertThat(document).as("a CSAF document without /document is not one").isNotNull();
        for (String required : DOCUMENT_REQUIRED) {
            assertThat(document.has(required))
                    .as("/document/%s is required by the CSAF 2.0 schema", required)
                    .isTrue();
        }
        for (String required : TRACKING_REQUIRED) {
            assertThat(document.get("tracking").has(required))
                    .as("/document/tracking/%s is required by the CSAF 2.0 schema", required)
                    .isTrue();
        }
    }

    @Test
    @DisplayName("says which version it claims, so the claim can be checked")
    void declaresItsVersion() throws Exception {
        assertThat(emit().get("document").get("csaf_version").asText()).isEqualTo("2.0");
    }

    @Test
    @DisplayName("carries a revision history that is not empty")
    void revisionHistoryIsNotEmpty() throws Exception {
        JsonNode history = emit().get("document").get("tracking").get("revision_history");

        assertThat(history.isArray()).isTrue();
        assertThat(history)
                .as("the schema requires the property; an empty array satisfies the letter and "
                        + "tells a reader nothing about when the advisory changed")
                .isNotEmpty();
        assertThat(history.get(0).has("date")).isTrue();
        assertThat(history.get(0).has("number")).isTrue();
        assertThat(history.get(0).has("summary")).isTrue();
    }

    private static JsonNode emit() throws Exception {
        CsafDocument document = CsafExport.build(
                List.of(ExportableIssue.builder()
                        .id(1)
                        .fingerprint("fp")
                        .type(FindingType.VULNERABILITY)
                        .identifier("CVE-2026-0001")
                        .build()),
                new CsafExport.Options(
                        "paiement-api",
                        "Example Corp",
                        "4.2.0",
                        "https://example.invalid",
                        Instant.parse("2026-09-14T08:00:00Z")));
        return MAPPER.readTree(MAPPER.writeValueAsString(document));
    }
}
