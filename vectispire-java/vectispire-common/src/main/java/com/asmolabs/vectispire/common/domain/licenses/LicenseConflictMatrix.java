package com.asmolabs.vectispire.common.domain.licenses;

import java.util.List;
import java.util.Locale;

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

    public record LicenseConflict(
            String packageName,
            String packageVersion,
            String licenseExpression,
            LicenseRiskCategory riskCategory,
            String targetKind,
            String targetName,
            Compatibility compatibility,
            String legalRiskExplanation,
            String remediationAdvice) {}

    public record CompatibilityCell(
            String targetLicenseType,
            String dependencyLicenseCategory,
            Compatibility compatibility,
            String ruleDescription) {}

    /**
     * Standard cross-compatibility matrix for commercial enterprise software.
     */
    public static List<CompatibilityCell> getStandardCompatibilityRules() {
        return List.of(
                new CompatibilityCell("PROPRIETARY_COMMERCIAL", "PERMISSIVE", Compatibility.COMPATIBLE, "Compatible sans obligation de divulgation de code source. Respecter l'attribution."),
                new CompatibilityCell("PROPRIETARY_COMMERCIAL", "WEAK_COPYLEFT", Compatibility.CONDITIONAL, "Liaison dynamique obligatoire (ex: JAR/DLL séparé). Les modifications directes de la librairie doivent être publiées."),
                new CompatibilityCell("PROPRIETARY_COMMERCIAL", "STRONG_COPYLEFT", Compatibility.INCOMPATIBLE_BLOCKING, "CONFLIT MAJEUR : Risque de contamination virale. Oblige légalement à divulguer l'intégralité du code source propriétaire."),
                new CompatibilityCell("PROPRIETARY_COMMERCIAL", "FORBIDDEN", Compatibility.INCOMPATIBLE_BLOCKING, "INTERDIT : Licence non commerciale ou commerciale payante non acquise."),

                new CompatibilityCell("OPEN_SOURCE_PERMISSIVE", "PERMISSIVE", Compatibility.COMPATIBLE, "Totalement compatible."),
                new CompatibilityCell("OPEN_SOURCE_PERMISSIVE", "WEAK_COPYLEFT", Compatibility.CONDITIONAL, "Compatible avec conservation de la notice de licence séparée."),
                new CompatibilityCell("OPEN_SOURCE_PERMISSIVE", "STRONG_COPYLEFT", Compatibility.CONDITIONAL, "Le projet combiné doit être redistribué sous licence GPL/AGPL."),

                new CompatibilityCell("GPL_COMPLIANT", "PERMISSIVE", Compatibility.COMPATIBLE, "Compatible (MIT/BSD/Apache sont intégrables dans un projet GPL)."),
                new CompatibilityCell("GPL_COMPLIANT", "STRONG_COPYLEFT", Compatibility.COMPATIBLE, "Compatible avec le même niveau de copyleft.")
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
        String normLic = licenseExpression != null ? licenseExpression.toUpperCase(Locale.ROOT) : "UNKNOWN";

        Compatibility compatibility;
        String explanation;
        String advice;

        if (category == LicenseRiskCategory.FORBIDDEN) {
            compatibility = Compatibility.INCOMPATIBLE_BLOCKING;
            explanation = String.format("La licence '%s' interdit l'usage commercial ou restreint la redistribution.", normLic);
            advice = "Remplacer immédiatement ce composant par une alternative sous licence Open Source standard (MIT, Apache-2.0, BSD).";
        } else if (category == LicenseRiskCategory.STRONG_COPYLEFT) {
            if (isProprietaryTarget) {
                compatibility = Compatibility.INCOMPATIBLE_BLOCKING;
                explanation = String.format("Contamination Copyleft Forte (%s) : Intégrer ce composant dans un produit propriétaire oblige légalement à ouvrir et publier le code source propriétaire de votre application.", normLic);
                advice = "Remplacer la dépendance par un équivalent sous licence permissive (MIT, Apache-2.0, BSD) ou isoler le composant via un microservice / process tiers indépendant.";
            } else {
                compatibility = Compatibility.CONDITIONAL;
                explanation = String.format("Licence Copyleft Forte (%s) : Votre projet doit être distribué sous licence compatible GPL.", normLic);
                advice = "Vérifier que la licence globale du dépôt est conforme aux exigences de réciprocité GPL/AGPL.";
            }
        } else if (category == LicenseRiskCategory.WEAK_COPYLEFT) {
            compatibility = Compatibility.CONDITIONAL;
            explanation = String.format("Copyleft Faible (%s) : La bibliothèque peut être utilisée dans un logiciel propriétaire à condition de ne pas être modifiée directement et d'être liée dynamiquement.", normLic);
            advice = "Conserver la dépendance sous forme de binaire non modifié (JAR/DLL) et inclure la notice de licence originale dans la documentation légale.";
        } else if (category == LicenseRiskCategory.PERMISSIVE) {
            compatibility = Compatibility.COMPATIBLE;
            explanation = String.format("Licence Permissive (%s) : Utilisable librement en contexte commercial et propriétaire.", normLic);
            advice = "Conserver les mentions de copyright et les notices d'attribution dans le fichier THIRD-PARTY-NOTICES / SBOM.";
        } else {
            compatibility = Compatibility.CONDITIONAL;
            explanation = "Licence inconnue ou non standard. Risque juridique non qualifié.";
            advice = "Effectuer une revue juridique du fichier de licence du composant.";
        }

        return new LicenseConflict(
                packageName,
                packageVersion,
                licenseExpression,
                category,
                targetKind,
                targetName,
                compatibility,
                explanation,
                advice);
    }
}
