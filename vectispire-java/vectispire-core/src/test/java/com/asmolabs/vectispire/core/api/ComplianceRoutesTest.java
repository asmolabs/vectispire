package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

@DisplayName("the compliance routes")
class ComplianceRoutesTest extends ApiTestBase {

    @Autowired
    private AuditLogRepository auditEntries;

    @Test
    @DisplayName("returns compliance summary across all frameworks")
    void returnsSummary() throws Exception {
        mvc.perform(authenticated(get("/api/v1/compliance/summary"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.evaluations").isArray())
                .andExpect(jsonPath("$.evaluations.length()").value(6))
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

        mvc.perform(authenticated(get("/api/v1/compliance/frameworks/soc-2"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.framework").value("SOC_2"))
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

    @Test
    @DisplayName("the PDF export audits the scope the summary read: ALL is the whole estate, not a target named ALL")
    void theExportAuditsTheScopeItRendered() throws Exception {
        mvc.perform(authenticated(get("/api/v1/compliance/export.pdf"), asAdmin())).andExpect(status().isOk());
        for (String estate : new String[] {"ALL", "undefined", " "}) {
            mvc.perform(authenticated(get("/api/v1/compliance/export.pdf").param("targetId", estate), asAdmin()))
                    .andExpect(status().isOk());
        }
        mvc.perform(authenticated(get("/api/v1/compliance/export.pdf?targetId=repo:7"), asAdmin()))
                .andExpect(status().isOk());

        // In the chain's order, not `findAll`'s: the keys are random UUIDs, and only SQLite's rowid
        // made the unordered read look like the order of the requests.
        assertThat(auditEntries.findAllByOrderByTimestampAscIdAsc())
                .filteredOn(entry -> AuditOperation.REPORT_EXPORTED.wireName().equals(entry.getOperationType()))
                .extracting(AuditLogEntity::getDescription)
                .containsExactly(
                        "Regulatory Compliance PDF report exported for the whole estate",
                        "Regulatory Compliance PDF report exported for the whole estate",
                        "Regulatory Compliance PDF report exported for the whole estate",
                        "Regulatory Compliance PDF report exported for the whole estate",
                        "Regulatory Compliance PDF report exported for repo:7");
    }

    @Test
    @DisplayName("a target written with neither prefix is refused in words, not a 500")
    void aTargetWithoutItsKindIsRefused() throws Exception {
        mvc.perform(authenticated(get("/api/v1/compliance/summary").param("targetId", "42"), asAdmin()))
                .andExpect(status().isBadRequest())
                .andExpect(result -> assertThat(detailOf(result))
                        .isEqualTo("A target is written repository:<id> or container:<id>."));
    }
}
