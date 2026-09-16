package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * What the published document claims is always sent, and what it deliberately does not claim.
 *
 * <p>{@link ClientContractSpecTest} already fails when the document changes, so a regression here
 * cannot pass unnoticed — but it would arrive as a large diff whose meaning has to be reconstructed
 * from the JSON. These three assertions say the intent instead: a primitive is required, a
 * reference type is not, and a renamed primitive is required <em>under the name it is sent by</em>.
 * The last one is the case that was wrong on the first run.
 */
@DisplayName("the document's required properties")
class PrimitiveRecordComponentsAreRequiredTest extends ApiTestBase {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    @DisplayName("mark a record's primitive components, under their serialised names")
    void mark_primitive_components() throws Exception {
        JsonNode schemas = document().get("components").get("schemas");

        // `boolean mustChangePassword` and `boolean mfaEnabled`: no absent value, no null value.
        assertThat(required(schemas.get("UserSummary")))
                .contains("mustChangePassword", "mfaEnabled");

        // `@JsonProperty("mfa_required") boolean mfaRequired` — the wire name, not the Java one.
        assertThat(required(schemas.get("LoginResponse"))).containsExactly("mfa_required");
    }

    @Test
    @DisplayName("stop at reference types, which the server may legitimately send as null")
    void leave_reference_types_optional() throws Exception {
        JsonNode schemas = document().get("components").get("schemas");

        // Every component of SetupResponse is a String; whether one is ever null is a property of
        // the code, and stating it belongs on the record rather than in a converter's guess.
        assertThat(required(schemas.get("SetupResponse"))).isEmpty();

        // `String username` is in practice always sent, and is still not claimed here.
        assertThat(required(schemas.get("UserSummary"))).doesNotContain("username", "displayName");
    }

    private JsonNode document() throws Exception {
        return MAPPER.readTree(mvc.perform(authenticated(get("/v3/api-docs"), asReader()))
                .andReturn()
                .getResponse()
                .getContentAsString());
    }

    private static List<String> required(JsonNode schema) {
        assertThat(schema).as("the schema is in the document").isNotNull();
        List<String> names = new ArrayList<>();
        JsonNode required = schema.get("required");
        if (required != null) {
            required.forEach(name -> names.add(name.asText()));
        }
        return names;
    }
}
