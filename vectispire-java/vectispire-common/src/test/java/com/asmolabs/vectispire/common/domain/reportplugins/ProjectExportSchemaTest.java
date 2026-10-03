package com.asmolabs.vectispire.common.domain.reportplugins;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The project export's published schema is a contract held like {@code openapi.json} (decision 0035 §1):
 * its bytes are pinned, so that a change to it is a decision — the version moved by the rule it states —
 * and never the side effect of an edit. Whether the generator agrees with it is {@code
 * ProjectExportRoutesTest}'s, which validates every export it builds.
 */
@DisplayName("the project export's schema")
class ProjectExportSchemaTest {

    /**
     * The SHA-256 of {@code v1.schema.json}. <b>Changing the schema changes this</b>, and the change is
     * reviewed as one: an added optional field is a minor ({@link ProjectExportSchema#VERSION} 1.1, and the
     * release notes say so); anything else — a field removed, renamed, retyped, or made required — is a new
     * major, in a new file, the previous one produced beside it for a release line.
     */
    private static final String V1_SHA256 = "7f903fc220981166ea7d8734e97ac84449963d587ee4b3e8b89e8ab15f831f41";

    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    @DisplayName("its bytes are pinned: a change to it is a reviewed change of version")
    void pinned() {
        byte[] schema = ProjectExportSchema.of(1).orElseThrow();
        assertThat(Digests.sha256Hex(schema))
                .as("v1.schema.json changed: move ProjectExportSchema.VERSION by the schema's own rule, say so in the "
                        + "release notes, then pin the new digest here")
                .isEqualTo(V1_SHA256);
    }

    @Test
    @DisplayName("it names the export and the version the code writes, and is draft 2020-12")
    void agreesWithTheCode() throws Exception {
        JsonNode schema = JSON.readTree(ProjectExportSchema.of(ProjectExportSchema.MAJOR).orElseThrow());
        assertThat(schema.path("$schema").asText()).isEqualTo("https://json-schema.org/draft/2020-12/schema");
        assertThat(schema.at("/properties/schema/const").asText()).isEqualTo(ProjectExportSchema.NAME);
        assertThat(ProjectExportSchema.VERSION).startsWith(ProjectExportSchema.MAJOR + ".")
                .matches(Pattern.compile(schema.at("/properties/schema_version/pattern").asText()));
    }

    @Test
    @DisplayName("every part of the export is a required property, under the name the JSON gives it")
    void everyPartIsRequired() throws Exception {
        JsonNode schema = JSON.readTree(ProjectExportSchema.of(ProjectExportSchema.MAJOR).orElseThrow());
        List<String> required = new ArrayList<>();
        schema.path("required").forEach(name -> required.add(name.asText()));
        List<String> parts = Arrays.stream(ProjectExport.class.getRecordComponents())
                .map(component -> component.getName().replaceAll("([A-Z])", "_$1").toLowerCase(java.util.Locale.ROOT))
                .toList();
        assertThat(required).containsExactlyElementsOf(parts);
    }

    @Test
    @DisplayName("a major this build does not produce has no schema")
    void otherMajors() {
        assertThat(ProjectExportSchema.of(0)).isEmpty();
        assertThat(ProjectExportSchema.of(2)).isEmpty();
    }
}
