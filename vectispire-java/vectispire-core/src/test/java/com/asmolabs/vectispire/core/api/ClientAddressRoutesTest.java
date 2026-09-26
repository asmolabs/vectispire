package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;

/**
 * The audit trail behind a proxy names the client, not the proxy.
 *
 * <p>MockMvc's peer is {@code 127.0.0.1}, declared a trusted proxy here, so the client is whatever
 * {@code X-Forwarded-For} says behind it. The throttles resolved the client this way; the audit
 * entries written through {@code RequestActors} and the access-denied handler read the peer and
 * named the load balancer on every line.
 */
@TestPropertySource(properties = "vectispire.security.trusted-proxies=127.0.0.1")
@DisplayName("the client's address behind a trusted proxy")
class ClientAddressRoutesTest extends ApiTestBase {

    private static final String CLIENT = "203.0.113.50";

    @Autowired
    private AuditLogRepository auditLog;

    @Test
    @DisplayName("an action a route audits is recorded with the client's address")
    void anAuditedActionNamesTheClient() throws Exception {
        mvc.perform(authenticated(put("/api/v1/settings"), asAdmin())
                        .header("X-Forwarded-For", CLIENT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("eol_warn_days", "31"))))
                .andExpect(status().isOk());

        assertThat(auditLog.findAll())
                .filteredOn(entry -> AuditOperation.SETTING_UPDATED.wireName().equals(entry.getOperationType()))
                .extracting(AuditLogEntity::getIpAddress)
                .containsOnly(CLIENT);
    }

    @Test
    @DisplayName("a refusal the chain audits is recorded with the client's address")
    void aRefusalNamesTheClient() throws Exception {
        mvc.perform(authenticated(get("/api/v1/users"), asReader()).header("X-Forwarded-For", CLIENT))
                .andExpect(status().isForbidden());

        assertThat(auditLog.findAll())
                .filteredOn(entry -> AuditOperation.ACCESS_DENIED.wireName().equals(entry.getOperationType()))
                .extracting(AuditLogEntity::getIpAddress)
                .containsOnly(CLIENT);
    }
}
