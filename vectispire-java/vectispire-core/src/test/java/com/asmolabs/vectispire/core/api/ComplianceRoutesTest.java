package com.asmolabs.vectispire.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

@DisplayName("the compliance routes")
class ComplianceRoutesTest extends ApiTestBase {

    @Test
    @DisplayName("returns compliance summary across all frameworks")
    void returnsSummary() throws Exception {
        mvc.perform(authenticated(get("/api/v1/compliance/summary"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.evaluations").isArray())
                .andExpect(jsonPath("$.evaluations.length()").value(5))
                .andExpect(jsonPath("$.evaluations[0].framework").value("NIS_2"))
                .andExpect(jsonPath("$.evaluations[0].controls").isArray());
    }

    @Test
    @DisplayName("returns detail for a specific framework")
    void returnsFrameworkDetail() throws Exception {
        mvc.perform(authenticated(get("/api/v1/compliance/frameworks/dora"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.framework").value("DORA"))
                .andExpect(jsonPath("$.controls").isArray())
                .andExpect(jsonPath("$.controls.length()").value(4));
    }

    @Test
    @DisplayName("exports compliance audit PDF")
    void exportsPdf() throws Exception {
        mvc.perform(authenticated(get("/api/v1/compliance/export.pdf"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_PDF));
    }
}
