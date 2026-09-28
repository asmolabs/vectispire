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
        expected.put("CRITICAL_KEV_DETECTED", "VECTI-SEC-002");
        expected.put("SECURITY_GATE_FAILED", "VECTI-SEC-003");
        expected.put("TRIAGE_SETTLED", "VECTI-SEC-005");
        expected.put("MFA_BACKUP_CODE_USED", "VECTI-SEC-006");
        expected.put("SIGN_IN_THROTTLED", "VECTI-SEC-007");
        expected.put("MFA_FAILURE_CEILING", "VECTI-SEC-008");
        expected.put("BEARER_TOKEN_THROTTLED", "VECTI-SEC-009");
        expected.put("ACCOUNT_CHANGED", "VECTI-SEC-010");
        expected.put("ACCESS_GRANT_CHANGED", "VECTI-SEC-011");
        expected.put("API_KEY_ISSUED", "VECTI-SEC-012");
        expected.put("API_KEY_REVOKED", "VECTI-SEC-013");
        expected.put("AGENT_CHANGED", "VECTI-SEC-014");
        expected.put("AGENT_RESULT_REFUSED", "VECTI-SEC-015");
        expected.put("TRIAGE_APPROVED", "VECTI-SEC-016");
        expected.put("TRIAGE_REFUSED", "VECTI-SEC-017");
        expected.put("AUDIT_CHAIN_BROKEN", "VECTI-SEC-018");
        expected.put("SECURITY_SETTING_CHANGED", "VECTI-SEC-019");
        expected.put("AGENT_SEALING_KEY_REFUSED", "VECTI-SEC-020");
        expected.put("PLUGIN_CHANGED", "VECTI-SEC-021");
        expected.put("SARIF_SOURCE_CHANGED", "VECTI-SEC-022");
        expected.put("SARIF_IMPORT_REFUSED", "VECTI-SEC-023");
        expected.put("CHECKLIST_TEMPLATE_CHANGED", "VECTI-SEC-024");
        expected.put("REPORT_IMPORT_REFUSED", "VECTI-SEC-027");
        expected.put("PING_TEST", "VECTI-SEC-999");

        Map<String, String> actual = Arrays.stream(SecurityEventType.values())
                .collect(Collectors.toMap(Enum::name, SecurityEventType::signatureId, (a, b) -> a, LinkedHashMap::new));
        assertThat(actual).containsExactlyEntriesOf(expected);
    }

    @Test
    @DisplayName("no identifier is used twice, and the two retired ones are never reused")
    void identifiersAreUniqueAndRetiredOnesStayRetired() {
        assertThat(Arrays.stream(SecurityEventType.values()).map(SecurityEventType::signatureId))
                .doesNotHaveDuplicates()
                .doesNotContain("VECTI-SEC-001", "VECTI-SEC-004");
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
        assertThat(SecurityEventType.signalledBy(AuditOperation.AGENT_SEALING_KEY_RESET))
                .contains(SecurityEventType.AGENT_CHANGED);
        assertThat(SecurityEventType.signalledBy(AuditOperation.AGENT_SEALING_KEY_REFUSED))
                .contains(SecurityEventType.AGENT_SEALING_KEY_REFUSED);
        // A rotation happens at every start of every agent: routine, not an event for a SOC.
        assertThat(SecurityEventType.signalledBy(AuditOperation.AGENT_SEALING_KEY_ACCEPTED)).isEmpty();
        assertThat(SecurityEventType.signalledBy(AuditOperation.GATE_POLICY_UPDATED))
                .contains(SecurityEventType.SECURITY_SETTING_CHANGED);
        assertThat(SecurityEventType.signalledBy(AuditOperation.PLUGIN_REGISTERED)).contains(SecurityEventType.PLUGIN_CHANGED);
        assertThat(SecurityEventType.signalledBy(AuditOperation.PLUGIN_ACTIVATED)).contains(SecurityEventType.PLUGIN_CHANGED);
        assertThat(SecurityEventType.signalledBy(AuditOperation.SARIF_SOURCE_CHANGED))
                .contains(SecurityEventType.SARIF_SOURCE_CHANGED);
        assertThat(SecurityEventType.signalledBy(AuditOperation.SARIF_IMPORT_REFUSED))
                .contains(SecurityEventType.SARIF_IMPORT_REFUSED);
        // A pipeline's upload is as frequent as its builds: the entry, not an event.
        assertThat(SecurityEventType.signalledBy(AuditOperation.SARIF_IMPORTED)).isEmpty();
        assertThat(SecurityEventType.signalledBy(AuditOperation.REPORT_IMPORT_REFUSED))
                .contains(SecurityEventType.REPORT_IMPORT_REFUSED);
        assertThat(SecurityEventType.signalledBy(AuditOperation.COVERAGE_IMPORTED)).isEmpty();
        assertThat(SecurityEventType.signalledBy(AuditOperation.TEST_REPORT_IMPORTED)).isEmpty();
        // What every project attests to changes when a version is published (decision 0032 §9).
        assertThat(SecurityEventType.signalledBy(AuditOperation.CHECKLIST_TEMPLATE_PUBLISHED))
                .contains(SecurityEventType.CHECKLIST_TEMPLATE_CHANGED);
        // A draft being written changes nothing any project attests to.
        assertThat(SecurityEventType.signalledBy(AuditOperation.CHECKLIST_TEMPLATE_IMPORTED)).isEmpty();
        assertThat(SecurityEventType.signalledBy(AuditOperation.CHECKLIST_TEMPLATE_LAYOUT_CONFIRMED)).isEmpty();
        assertThat(SecurityEventType.signalledBy(AuditOperation.CHECKLIST_TEMPLATE_ITEMS_PAIRED)).isEmpty();
        assertThat(SecurityEventType.signalledBy(AuditOperation.CHECKLIST_TEMPLATE_DERIVED)).isEmpty();
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
        // A published version retired is VECTI-SEC-024, a draft set aside is nothing: the writer names it.
        assertThat(SecurityEventType.signalledBy(AuditOperation.CHECKLIST_TEMPLATE_RETIRED)).isEmpty();
        assertThat(SecurityEventType.signalledBy(null)).isEmpty();
    }
}
