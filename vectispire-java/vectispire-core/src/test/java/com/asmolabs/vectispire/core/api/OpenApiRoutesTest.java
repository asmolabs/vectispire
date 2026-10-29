package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The API's own map, and who may read it.
 *
 * <p>Two settings stand between a caller and this document, and they answer different
 * questions. {@code springdoc.api-docs.enabled} decides whether it is generated at all — off by
 * default, so a production instance serves nothing. {@code
 * vectispire.security.anonymous-api-docs} decides who may read it when it is generated, and is
 * also off by default: a complete endpoint catalogue is exactly the reconnaissance a control
 * plane like this one reports on other people's deployments, and handing it out unauthenticated
 * should be a decision somebody took rather than one they inherited.
 *
 * <p>This suite runs with generation on, which is the only configuration in which the second
 * question is even askable.
 */
@DisplayName("OpenAPI 3.0 & Swagger UI documentation routes")
class OpenApiRoutesTest extends ApiTestBase {

    @Test
    @DisplayName("serves the OpenAPI 3.0 specification to an authenticated caller")
    void exposesOpenApiSpecification() throws Exception {
        mvc.perform(authenticated(get("/v3/api-docs"), asReader()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.openapi").exists())
                .andExpect(jsonPath("$.info.title").value("Vectispire Control Plane REST API"))
                // The version is DocumentVersionRoutesTest's: it is the build's, and this line used to
                // pin "4.1.0", a number no release of Vectispire ever carried.
                .andExpect(jsonPath("$.paths['/api/v1/auth/login']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/attack-surface']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/repositories']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/scans']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/compliance/summary']").exists());
    }

    @Test
    @DisplayName("a plugin's state is one of decision 0017's four, a refusal and a footing are closed, and an import's tools are a list of strings")
    void closesThePluginContract() throws Exception {
        mvc.perform(authenticated(get("/v3/api-docs"), asReader()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.components.schemas.PluginOutcome.properties.state.enum",
                        Matchers.contains("produced", "not_applicable", "absent", "refused")))
                .andExpect(jsonPath("$.components.schemas.PluginOutcome.properties.refusal.enum",
                        Matchers.contains("unsigned", "signature_unverified", "registry_authentication_required")))
                .andExpect(jsonPath("$.components.schemas.PluginOutcome.properties.signature.enum",
                        Matchers.contains("verified", "waived", "not_required")))
                .andExpect(jsonPath("$.components.schemas.SarifImportView.properties.tools.type").value("array"))
                .andExpect(jsonPath("$.components.schemas.SarifImportView.properties.tools.items.type").value("string"))
                .andExpect(jsonPath("$.components.schemas.SarifSourceView.properties.apiKeyName.type").value("string"))
                // A string, or null when a deletion races the read (ResponseNullabilityTest).
                .andExpect(jsonPath("$.components.schemas.PluginActivationView.properties.projectName.type",
                        Matchers.contains("string", "null")))
                .andExpect(jsonPath("$.components.schemas.PluginActivationView.properties.solutionName.type",
                        Matchers.contains("string", "null")));
    }

    @Test
    @DisplayName("the SCIM routes declare exactly the refusals they answer, in SCIM's error schema, and a creation's 201")
    void declaresTheScimRefusals() throws Exception {
        // The routes answered 404 and 409 in ScimErrorResponse since 0.11.1 while the document declared a
        // 200 alone (and a 200 for a creation that answers 201): a client generated from it had no type
        // for the body a directory reads `scimType` from. The 400s (invalidFilter on the list, an
        // attribute refused elsewhere) and the 403 on an administrative account stayed undeclared after
        // that. Each set below is what the handler answers, read from the service and pinned by
        // ScimUsersRoutesTest and ScimGroupsRoutesTest: a status declared and never answered is a branch
        // a generated client writes for nothing, one answered and undeclared is a body it has no type for.
        Map<String, Map<String, List<String>>> answered = Map.of(
                "/scim/v2/Users", Map.of(
                        "get", List.of("200", "400"),
                        "post", List.of("201", "400", "409")),
                "/scim/v2/Users/{id}", Map.of(
                        "get", List.of("200", "404"),
                        "put", List.of("200", "400", "403", "404", "409"),
                        "patch", List.of("200", "400", "403", "404"),
                        "delete", List.of("204", "403")),
                "/scim/v2/Groups", Map.of(
                        "get", List.of("200"),
                        "post", List.of("201", "400", "409")),
                "/scim/v2/Groups/{id}", Map.of(
                        "get", List.of("200", "404"),
                        "put", List.of("200", "400", "404", "409"),
                        "patch", List.of("200", "400", "404", "409"),
                        "delete", List.of("204")));

        var spec = json.readTree(mvc.perform(authenticated(get("/v3/api-docs"), asReader()))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
        assertThat(spec.at("/components/schemas/ScimErrorResponse/properties/scimType/type").asText())
                .isEqualTo("string");

        answered.forEach((path, operations) -> operations.forEach((method, statuses) -> {
            var responses = spec.path("paths").path(path).path(method).path("responses");
            List<String> declared = new ArrayList<>();
            responses.fieldNames().forEachRemaining(declared::add);
            assertThat(declared).as("%s %s", method, path).containsExactlyInAnyOrderElementsOf(statuses);

            String dto = "#/components/schemas/Scim" + (path.contains("Users") ? "User" : "Group") + "Dto";
            for (String code : statuses) {
                String schema = responses.path(code).path("content").path("application/scim+json")
                        .path("schema").path("$ref").asText();
                if (code.startsWith("4")) {
                    assertThat(schema).as("%s %s %s", method, path, code)
                            .isEqualTo("#/components/schemas/ScimErrorResponse");
                } else if (code.equals("201") || (code.equals("200") && path.endsWith("{id}"))) {
                    assertThat(schema).as("%s %s %s", method, path, code).isEqualTo(dto);
                }
            }
        }));
    }

    @Test
    @DisplayName("refuses the specification to an anonymous caller unless the setting says otherwise")
    void refusesTheSpecificationAnonymously() throws Exception {
        // The default this test pins. It used to be `permitAll` with no way to say otherwise,
        // so switching the documentation on switched it on for everybody — including a scanner
        // that reads it to enumerate what to try.
        mvc.perform(get("/v3/api-docs"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("serves Swagger UI to an authenticated caller")
    void servesSwaggerUi() throws Exception {
        mvc.perform(authenticated(get("/swagger-ui.html"), asReader()))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    @DisplayName("the UI's own configuration path is refused anonymously too")
    void refusesTheSwaggerConfigAnonymously() throws Exception {
        // `/v3/api-docs/swagger-config` is a separate path the UI fetches for itself. Left open
        // while the rest was closed it discloses the group layout, and left closed while the
        // rest was open it renders an empty page — which is why the rule is a prefix rather
        // than a list of three literals.
        mvc.perform(get("/v3/api-docs/swagger-config"))
                .andExpect(status().isUnauthorized());
    }
}
