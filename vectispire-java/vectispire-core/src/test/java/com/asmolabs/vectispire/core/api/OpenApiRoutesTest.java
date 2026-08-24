package com.asmolabs.vectispire.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("OpenAPI 3.0 & Swagger UI documentation routes")
class OpenApiRoutesTest extends ApiTestBase {

    @Test
    @DisplayName("exposes OpenAPI 3.0 JSON specification publicly")
    void exposesOpenApiSpecification() throws Exception {
        mvc.perform(get("/v3/api-docs"))
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
    @DisplayName("serves Swagger UI endpoint without requiring prior authentication")
    void servesSwaggerUi() throws Exception {
        mvc.perform(get("/swagger-ui.html"))
                .andExpect(status().is3xxRedirection());
    }
}
