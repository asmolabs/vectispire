package com.asmolabs.vectispire.common.domain.licenses;

import java.util.List;

/**
 * Cross-license compatibility analysis, copyleft contamination detection,
 * and commercial distribution legal risk evaluation.
 */
public final class LicenseConflictMatrix {

    private LicenseConflictMatrix() {}

    public enum Compatibility {
        COMPATIBLE,
        CONDITIONAL,
        INCOMPATIBLE_BLOCKING
    }

    /**
     * What the licence means for this target, as a token the screen turns into two sentences.
     *
     * <p><b>A token and not a sentence</b>, for the reason {@code RemediationGap} states: the
     * legal explanation and the remediation advice are screen text, and screen text is translated
     * on the client. Both used to be French sentences the licences screen printed as they stood,
     * under column headers that went through the translation bundle.
     *
     * <p>One token rather than two: the explanation and the advice are never chosen separately —
     * each branch below settles both at once — so two fields would have allowed a pair that says
     * one thing and advises another.
     */
    public enum ConflictVerdict {
        /** Non-commercial, or a paid licence nobody bought. */
        FORBIDDEN_LICENCE,
        /** Strong copyleft linked into a proprietary target: the reciprocal obligation bites. */
        STRONG_COPYLEFT_PROPRIETARY,
        /** Strong copyleft in a target that is itself distributed under a compatible licence. */
        STRONG_COPYLEFT_RECIPROCAL,
        WEAK_COPYLEFT,
        PERMISSIVE,
        /** Not a licence this matrix recognises — an open legal question, not a clean bill. */
        UNKNOWN_LICENCE
    }

    public record LicenseConflict(
            String packageName,
            String packageVersion,
            String licenseExpression,
            LicenseRiskCategory riskCategory,
            String targetKind,
            String targetName,
            Compatibility compatibility,
            ConflictVerdict verdict) {}

    /** The note a matrix cell carries, as a token; the sentence lives in the client's bundles. */
    public enum RuleNote {
        PERMISSIVE_IN_PROPRIETARY,
        WEAK_COPYLEFT_IN_PROPRIETARY,
        STRONG_COPYLEFT_IN_PROPRIETARY,
        FORBIDDEN_IN_PROPRIETARY,
        PERMISSIVE_IN_PERMISSIVE,
        WEAK_COPYLEFT_IN_PERMISSIVE,
        STRONG_COPYLEFT_IN_PERMISSIVE,
        PERMISSIVE_IN_GPL,
        STRONG_COPYLEFT_IN_GPL
    }

    public record CompatibilityCell(
            String targetLicenseType,
            String dependencyLicenseCategory,
            Compatibility compatibility,
            RuleNote note) {}

    /**
     * Standard cross-compatibility matrix for commercial enterprise software.
     */
    public static List<CompatibilityCell> getStandardCompatibilityRules() {
        return List.of(
                new CompatibilityCell("PROPRIETARY_COMMERCIAL", "PERMISSIVE", Compatibility.COMPATIBLE, RuleNote.PERMISSIVE_IN_PROPRIETARY),
                new CompatibilityCell("PROPRIETARY_COMMERCIAL", "WEAK_COPYLEFT", Compatibility.CONDITIONAL, RuleNote.WEAK_COPYLEFT_IN_PROPRIETARY),
                new CompatibilityCell("PROPRIETARY_COMMERCIAL", "STRONG_COPYLEFT", Compatibility.INCOMPATIBLE_BLOCKING, RuleNote.STRONG_COPYLEFT_IN_PROPRIETARY),
                new CompatibilityCell("PROPRIETARY_COMMERCIAL", "FORBIDDEN", Compatibility.INCOMPATIBLE_BLOCKING, RuleNote.FORBIDDEN_IN_PROPRIETARY),

                new CompatibilityCell("OPEN_SOURCE_PERMISSIVE", "PERMISSIVE", Compatibility.COMPATIBLE, RuleNote.PERMISSIVE_IN_PERMISSIVE),
                new CompatibilityCell("OPEN_SOURCE_PERMISSIVE", "WEAK_COPYLEFT", Compatibility.CONDITIONAL, RuleNote.WEAK_COPYLEFT_IN_PERMISSIVE),
                new CompatibilityCell("OPEN_SOURCE_PERMISSIVE", "STRONG_COPYLEFT", Compatibility.CONDITIONAL, RuleNote.STRONG_COPYLEFT_IN_PERMISSIVE),

                new CompatibilityCell("GPL_COMPLIANT", "PERMISSIVE", Compatibility.COMPATIBLE, RuleNote.PERMISSIVE_IN_GPL),
                new CompatibilityCell("GPL_COMPLIANT", "STRONG_COPYLEFT", Compatibility.COMPATIBLE, RuleNote.STRONG_COPYLEFT_IN_GPL)
        );
    }

    /**
     * Evaluates compatibility for a dependency against a proprietary or commercial release context.
     */
    public static LicenseConflict evaluate(
            String packageName,
            String packageVersion,
            String licenseExpression,
            String targetKind,
            String targetName,
            boolean isProprietaryTarget) {

        LicenseRiskCategory category = LicenseRiskCategory.classify(licenseExpression);

        Compatibility compatibility;
        ConflictVerdict verdict;

        if (category == LicenseRiskCategory.FORBIDDEN) {
            compatibility = Compatibility.INCOMPATIBLE_BLOCKING;
            verdict = ConflictVerdict.FORBIDDEN_LICENCE;
        } else if (category == LicenseRiskCategory.STRONG_COPYLEFT) {
            if (isProprietaryTarget) {
                compatibility = Compatibility.INCOMPATIBLE_BLOCKING;
                verdict = ConflictVerdict.STRONG_COPYLEFT_PROPRIETARY;
            } else {
                compatibility = Compatibility.CONDITIONAL;
                verdict = ConflictVerdict.STRONG_COPYLEFT_RECIPROCAL;
            }
        } else if (category == LicenseRiskCategory.WEAK_COPYLEFT) {
            compatibility = Compatibility.CONDITIONAL;
            verdict = ConflictVerdict.WEAK_COPYLEFT;
        } else if (category == LicenseRiskCategory.PERMISSIVE) {
            compatibility = Compatibility.COMPATIBLE;
            verdict = ConflictVerdict.PERMISSIVE;
        } else {
            compatibility = Compatibility.CONDITIONAL;
            verdict = ConflictVerdict.UNKNOWN_LICENCE;
        }

        return new LicenseConflict(
                packageName,
                packageVersion,
                licenseExpression,
                category,
                targetKind,
                targetName,
                compatibility,
                verdict);
    }
}
