package com.asmolabs.vectispire.common.domain.vex;

import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.issues.VexJustification;
import java.util.Optional;

/**
 * What one issue's triage states about a product, before any VEX format spells it (decision 0041 §3).
 *
 * <p><b>One reading, three spellings.</b> CycloneDX, OpenVEX and CSAF each mapped the triage by hand, and
 * the three disagreed: OpenVEX looked for {@code false_positive} and {@code accepted_risk}, statuses that
 * never existed, so every approved {@code not_affected} left as {@code affected} there while the other two
 * said it was cleared; one CSAF path dropped {@code pending_approval} from every list. A customer comparing
 * two signed documents about one product saw two products. Every generator now asks this, and only
 * spells the answer.
 *
 * <p><b>A justification is never invented.</b> A {@code not_affected} row without one — older than the
 * rule that requires it, or imported — is nobody's claim that the product is unaffected, so it reads as
 * under investigation; two generators used to fill the gap with a justification of their own choosing,
 * in a signed document. Absent is not a value (decision 0007).
 *
 * @param justification present for {@link Kind#NOT_AFFECTED} only
 */
public record VexDisposition(Kind kind, Optional<VexJustification> justification) {

    public enum Kind {
        /** Nobody has concluded: under review, awaiting approval, or a clearance nobody justified. */
        UNDER_INVESTIGATION,
        /** Exposed. */
        AFFECTED,
        /** Exposed, and the team decided not to fix it: {@link TriageStatus#WILL_NOT_FIX}. */
        WILL_NOT_FIX,
        /** Not exposed, for the recorded reason. */
        NOT_AFFECTED,
        /** Fixed, or no longer found. */
        FIXED
    }

    public VexDisposition {
        justification = justification == null ? Optional.empty() : justification;
        if ((kind == Kind.NOT_AFFECTED) != justification.isPresent()) {
            throw new IllegalArgumentException("A justification goes with not_affected, and only with it.");
        }
    }

    /**
     * @param status the triage, or null for an issue nobody triaged
     * @param justification the recorded justification's wire name, or null
     * @param resolved whether the issue was no longer found by a scan that looked for it
     */
    public static VexDisposition of(TriageStatus status, String justification, boolean resolved) {
        if (resolved || status == TriageStatus.FIXED) {
            return new VexDisposition(Kind.FIXED, Optional.empty());
        }
        if (status == null) {
            return new VexDisposition(Kind.UNDER_INVESTIGATION, Optional.empty());
        }
        return switch (status) {
            case UNDER_REVIEW, PENDING_APPROVAL -> new VexDisposition(Kind.UNDER_INVESTIGATION, Optional.empty());
            case AFFECTED -> new VexDisposition(Kind.AFFECTED, Optional.empty());
            case WILL_NOT_FIX -> new VexDisposition(Kind.WILL_NOT_FIX, Optional.empty());
            case NOT_AFFECTED -> VexJustification.fromWireName(justification)
                    .map(known -> new VexDisposition(Kind.NOT_AFFECTED, Optional.of(known)))
                    .orElseGet(() -> new VexDisposition(Kind.UNDER_INVESTIGATION, Optional.empty()));
            case FIXED -> new VexDisposition(Kind.FIXED, Optional.empty());
        };
    }

    /** The same, from the wire names a view carries; an unknown status reads as nobody's conclusion. */
    public static VexDisposition of(String status, String justification, boolean resolved) {
        return of(TriageStatus.fromWireName(status).orElse(null), justification, resolved);
    }

    /**
     * CycloneDX's justification for an OpenVEX/CSAF one: the two vocabularies differ, and CycloneDX's
     * schema accepts only its own. The pairs are the ones CycloneDX publishes for converting between them.
     */
    public static String cycloneDxJustification(VexJustification justification) {
        return switch (justification) {
            case COMPONENT_NOT_PRESENT, VULNERABLE_CODE_NOT_PRESENT -> "code_not_present";
            case VULNERABLE_CODE_NOT_IN_EXECUTE_PATH -> "code_not_reachable";
            case VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY -> "requires_environment";
            case INLINE_MITIGATIONS_ALREADY_EXIST -> "protected_by_mitigating_control";
        };
    }
}
