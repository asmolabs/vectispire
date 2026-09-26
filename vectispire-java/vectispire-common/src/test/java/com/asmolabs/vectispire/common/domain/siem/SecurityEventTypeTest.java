package com.asmolabs.vectispire.common.domain.siem;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("the SIEM event catalogue")
class SecurityEventTypeTest {

    @Test
    @DisplayName("the signature identifiers are the contract a SOC's rules are written against")
    void signatureIdentifiersAreFrozen() {
        // Changing one of these silently disarms every correlation rule written against it, in
        // somebody else's SIEM. A change here has to be a decision, made in this file on purpose.
        Map<String, String> expected = new LinkedHashMap<>();
        expected.put("CRITICAL_KEV_DETECTED", "ZAN-SEC-002");
        expected.put("SECURITY_GATE_FAILED", "ZAN-SEC-003");
        expected.put("TRIAGE_SETTLED", "ZAN-SEC-005");
        expected.put("MFA_BACKUP_CODE_USED", "ZAN-SEC-006");
        expected.put("SIGN_IN_THROTTLED", "ZAN-SEC-007");
        expected.put("MFA_FAILURE_CEILING", "ZAN-SEC-008");
        expected.put("BEARER_TOKEN_THROTTLED", "ZAN-SEC-009");
        expected.put("ACCOUNT_CHANGED", "ZAN-SEC-010");
        expected.put("ACCESS_GRANT_CHANGED", "ZAN-SEC-011");
        expected.put("API_KEY_ISSUED", "ZAN-SEC-012");
        expected.put("API_KEY_REVOKED", "ZAN-SEC-013");
        expected.put("AGENT_CHANGED", "ZAN-SEC-014");
        expected.put("AGENT_RESULT_REFUSED", "ZAN-SEC-015");
        expected.put("TRIAGE_APPROVED", "ZAN-SEC-016");
        expected.put("TRIAGE_REFUSED", "ZAN-SEC-017");
        expected.put("AUDIT_CHAIN_BROKEN", "ZAN-SEC-018");
        expected.put("SECURITY_SETTING_CHANGED", "ZAN-SEC-019");
        expected.put("PING_TEST", "ZAN-SEC-999");

        Map<String, String> actual = Arrays.stream(SecurityEventType.values())
                .collect(Collectors.toMap(Enum::name, SecurityEventType::signatureId, (a, b) -> a, LinkedHashMap::new));
        assertThat(actual).containsExactlyEntriesOf(expected);
    }

    @Test
    @DisplayName("no identifier is used twice, and the two retired ones are never reused")
    void identifiersAreUniqueAndRetiredOnesStayRetired() {
        assertThat(Arrays.stream(SecurityEventType.values()).map(SecurityEventType::signatureId))
                .doesNotHaveDuplicates()
                .doesNotContain("ZAN-SEC-001", "ZAN-SEC-004");
    }

    @Test
    @DisplayName("every severity is a CEF severity")
    void severitiesAreInRange() {
        assertThat(SecurityEventType.values()).allSatisfy(type -> assertThat(type.cefSeverity()).isBetween(0, 10));
    }

    @Test
    @DisplayName("the unambiguous audit operations signal their event on their own")
    void operationsThatSignal() {
        assertThat(SecurityEventType.signalledBy(AuditOperation.API_KEY_CREATED)).contains(SecurityEventType.API_KEY_ISSUED);
        assertThat(SecurityEventType.signalledBy(AuditOperation.API_KEY_DELETED)).contains(SecurityEventType.API_KEY_REVOKED);
        assertThat(SecurityEventType.signalledBy(AuditOperation.TEAM_ACCESS_CHANGED))
                .contains(SecurityEventType.ACCESS_GRANT_CHANGED);
        assertThat(SecurityEventType.signalledBy(AuditOperation.USER_UPDATED)).contains(SecurityEventType.ACCOUNT_CHANGED);
        assertThat(SecurityEventType.signalledBy(AuditOperation.PROJECT_REPOSITORIES_CHANGED))
                .contains(SecurityEventType.ACCESS_GRANT_CHANGED);
        assertThat(SecurityEventType.signalledBy(AuditOperation.PROJECT_UPDATED)).isEmpty();
        assertThat(SecurityEventType.signalledBy(AuditOperation.AGENT_UPDATED)).contains(SecurityEventType.AGENT_CHANGED);
        assertThat(SecurityEventType.signalledBy(AuditOperation.AGENT_SIGNING_KEY_PINNED))
                .contains(SecurityEventType.AGENT_CHANGED);
        assertThat(SecurityEventType.signalledBy(AuditOperation.GATE_POLICY_UPDATED))
                .contains(SecurityEventType.SECURITY_SETTING_CHANGED);
    }

    @Test
    @DisplayName("the ambiguous ones signal nothing by themselves: their writers name the event")
    void ambiguousOperationsDoNotSignal() {
        // LOGIN_BLOCKED is also "password sign-in is disabled"; SETTING_UPDATED is also a branch
        // name; ISSUE_TRIAGED is also a ticket link. Mapped by operation, each would flood a SOC.
        assertThat(SecurityEventType.signalledBy(AuditOperation.LOGIN_BLOCKED)).isEmpty();
        assertThat(SecurityEventType.signalledBy(AuditOperation.SETTING_UPDATED)).isEmpty();
        assertThat(SecurityEventType.signalledBy(AuditOperation.ISSUE_TRIAGED)).isEmpty();
        assertThat(SecurityEventType.signalledBy(AuditOperation.ACCESS_DENIED)).isEmpty();
        assertThat(SecurityEventType.signalledBy(AuditOperation.LOGIN_SUCCESS)).isEmpty();
        assertThat(SecurityEventType.signalledBy(null)).isEmpty();
    }
}
