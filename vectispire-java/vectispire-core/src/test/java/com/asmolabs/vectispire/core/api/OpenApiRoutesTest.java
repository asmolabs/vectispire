package com.asmolabs.vectispire.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

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
                .andExpect(jsonPath("$.info.version").value("4.1.0"))
                .andExpect(jsonPath("$.paths['/api/v1/auth/login']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/attack-surface']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/repositories']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/scans']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/compliance/summary']").exists());
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
