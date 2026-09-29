package com.asmolabs.vectispire.common.domain.compliance;

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

    /**
     * A control's verdict, and a framework's.
     *
     * <p>The first three are a scale, best to worst, and their order is read ({@code worseOf} in the
     * engine). {@link #NO_DATA} is not on it: nothing was observed for the control to rest on.
     */
    public enum Status {
        COMPLIANT,
        PARTIAL,
        NON_COMPLIANT,
        /**
         * Nothing measured this control: no target has been scanned successfully (decision 0007 —
         * absent is not empty). <b>The engine read an empty estate as a clean one</b>: with no scan at
         * all, ISO 27001's secure coding, configuration and secrets controls read compliant on zero
         * findings nobody looked for, and the SoA called a declaration consistent with that.
         */
        NO_DATA;

        /** Whether this is a verdict at all — every status but {@link #NO_DATA}. */
        public boolean measured() {
            return this != NO_DATA;
        }
    }
}
