package com.asmolabs.vectispire.common.domain.siem;

/**
 * High-priority security incident and governance events forwarded to SOC/SIEM systems.
 */
public enum SecurityEventType {
    SECRET_LEAK_DETECTED("ZAN-SEC-001", "Secret Leak Detected", 10),
    CRITICAL_KEV_DETECTED("ZAN-SEC-002", "Actively Exploited Vulnerability (KEV)", 10),
    SECURITY_GATE_FAILED("ZAN-SEC-003", "Security Gate Policy Failure", 8),
    SLA_BREACH_DETECTED("ZAN-SEC-004", "Remediation SLA Breach", 7),
    SECURITY_POLICY_OVERRIDE("ZAN-SEC-005", "Security Risk Acceptance Override", 6),
    MFA_BACKUP_CODE_USED("ZAN-SEC-006", "Emergency MFA Backup Code Consumed", 6),
    SUSPICIOUS_LOGIN_ATTEMPT("ZAN-SEC-007", "Rate Limited Authentication Failure", 7),
    PING_TEST("ZAN-SEC-999", "SIEM Connector Health Check Ping", 1);

    private final String signatureId;
    private final String description;
    private final int cefSeverity;

    SecurityEventType(String signatureId, String description, int cefSeverity) {
        this.signatureId = signatureId;
        this.description = description;
        this.cefSeverity = cefSeverity;
    }

    public String signatureId() {
        return signatureId;
    }

    public String description() {
        return description;
    }

    public int cefSeverity() {
        return cefSeverity;
    }
}
