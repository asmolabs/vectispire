package com.asmolabs.zanshin.common.domain.compliance;

/**
 * A specific compliance requirement / control within a regulatory framework.
 */
public record ComplianceControl(
        String id,
        String name,
        String requirement,
        Category category) {

    public enum Category {
        VULNERABILITY_MANAGEMENT,
        SUPPLY_CHAIN,
        SECRETS_MANAGEMENT,
        SECURE_CODING,
        INFRASTRUCTURE_AS_CODE,
        GOVERNANCE,
        AUDIT_AND_LOGGING
    }

    public enum Status {
        COMPLIANT,
        PARTIAL,
        NON_COMPLIANT
    }
}
