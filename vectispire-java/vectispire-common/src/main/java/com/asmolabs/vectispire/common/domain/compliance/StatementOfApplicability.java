package com.asmolabs.vectispire.common.domain.compliance;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * What an organisation <em>says</em> about each control, set against what the tooling
 * <em>measures</em>.
 *
 * <h2>Why a product that measures controls needs a document that declares them</h2>
 *
 * <p><b>The declaration of applicability is the ISO 27001 document.</b> Clause 6.1.3 d requires
 * one: every Annex A control addressed, each either applicable or excluded, exclusions justified.
 * An assessment opens with it and works outwards. A tool that evaluates controls automatically
 * and holds no declaration answers a question nobody asked — it says how things are, and the
 * assessor came to check what you claimed against how things are.
 *
 * <p>Which is the whole value here: <b>the interesting artefact is not the declaration and not
 * the measurement, it is the disagreement between them.</b> A control declared implemented that
 * the estate measures non-compliant is precisely what an assessor writes up, and neither half of
 * the product could see it alone.
 *
 * <h2>The trap this model exists to avoid</h2>
 *
 * <p><b>Vectispire measures a slice of each control, never the whole of it.</b> A.8.8 is the
 * management of technical vulnerabilities — scanning is part of it, and so are the advisory
 * feeds, the risk assessments and the patching process that live nowhere near this database.
 * A.5.15 is access control, of which "no credentials in source code" is a corner.
 *
 * <p>So a reconciliation that treated every measurement as a verdict on the whole control would
 * manufacture findings: it would report an organisation as contradicting itself on access control
 * because a secret scanner had an opinion. {@link EvidenceSource} is what prevents that. A
 * declaration says where its evidence lives, and a control evidenced elsewhere is reported as
 * {@link Divergence#NOT_MEASURED_HERE} — an instruction to go and read the other document, not a
 * finding.
 */
public final class StatementOfApplicability {

    private StatementOfApplicability() {}

    /** Applicable, or excluded from the scope of the management system. */
    public enum Applicability {
        APPLICABLE,
        /** Excluded — which clause 6.1.3 d allows, and only with a justification. */
        EXCLUDED
    }

    /** How far the control has actually been put in place. */
    public enum Implementation {
        IMPLEMENTED,
        PARTIALLY_IMPLEMENTED,
        PLANNED,
        NOT_IMPLEMENTED
    }

    /**
     * Where the evidence for this control lives.
     *
     * <p>Not a formality: it decides whether this product's measurement is <em>about</em> the
     * declaration at all. See the class note.
     */
    public enum EvidenceSource {
        /** Vectispire's measurement is the evidence. */
        VECTISPIRE,
        /** Evidenced outside this product; {@code externalEvidence} says where. */
        EXTERNAL,
        /** Both, so the measurement is evidence for part of the control. */
        BOTH
    }

    /**
     * One line of the declaration, as an organisation wrote it.
     *
     * @param controlId the control's id within {@code framework}, e.g. {@code ISO-A.8.8}
     * @param justification why applicable, or — for an exclusion — why not. Required to exclude
     * @param implementation how far it is in place; meaningless, and ignored, when excluded
     * @param externalEvidence where the evidence lives when it is not here. Required for
     *     {@link EvidenceSource#EXTERNAL} and {@link EvidenceSource#BOTH}
     * @param owner the person accountable for the control, not for this row
     * @param reviewedAt when somebody last confirmed this line still holds
     * @param framework la clé du référentiel, <b>et une chaîne parce qu'elle en est réellement
     *     une</b>. Elle a porté {@link ComplianceFramework} tant que la table ne stockait que les
     *     six référentiels que le moteur évalue. Le Top 10 OWASP s'y déclare aussi désormais — ses
     *     catégories hors de portée d'une analyse statique n'ont que la déclaration pour porter une
     *     revue — et il n'est pas un référentiel de conformité : l'ajouter à l'énumération le ferait
     *     apparaître dans les évaluations et les résumés. La typer en énumération ne l'empêchait pas
     *     de contenir autre chose : la conversion rendait {@code null} sur une valeur inconnue, ce
     *     qui transforme un référentiel non prévu en ligne absente plutôt qu'en erreur. C'est le
     *     type qui était faux, pas la donnée
     * @param reviewDueAt when it must be confirmed again
     */
    public record Declaration(
            String framework,
            String controlId,
            Applicability applicability,
            String justification,
            Implementation implementation,
            EvidenceSource evidenceSource,
            String externalEvidence,
            String owner,
            String decidedBy,
            Instant decidedAt,
            Instant reviewedAt,
            Instant reviewDueAt) {

        /** A review is due and has not happened. */
        public boolean reviewOverdue(Instant now) {
            return reviewDueAt != null && reviewDueAt.isBefore(now);
        }
    }

    /**
     * What the declaration and the measurement do to each other.
     *
     * <p>Ordered worst first, so a sort puts what an assessor opens with at the top.
     */
    public enum Divergence {
        /**
         * Declared implemented; measured non-compliant. <b>The finding.</b>
         *
         * <p>It is worth being clear about why this outranks everything else: the organisation is
         * not merely short of a control, it has told its assessor otherwise in writing. That is a
         * different conversation, and it is the one the tool can start early.
         */
        CONTRADICTED,
        /** Excluded with no justification — clause 6.1.3 d requires one. */
        EXCLUDED_WITHOUT_JUSTIFICATION,
        /** The framework has this control and the declaration does not mention it. */
        UNDECLARED,
        /** Declared implemented; measured partial. Overstated rather than untrue. */
        OVERSTATED,
        /**
         * Declared planned or not implemented; measured compliant.
         *
         * <p>Harmless to the estate and still worth showing: it means the document has drifted
         * behind the practice, and an assessor reading a stale declaration asks why.
         */
        UNDERSTATED,
        /**
         * Evidenced outside this product, so nothing here bears on the claim.
         *
         * <p><b>Not a gap.</b> It is the model declining to have an opinion, which is the correct
         * behaviour and the reason the reconciliation can be trusted on the lines where it does.
         */
        NOT_MEASURED_HERE,
        /** Declared excluded, with a justification. Nothing to reconcile. */
        NOT_APPLICABLE,
        /** The declaration and the measurement agree. */
        CONSISTENT;

        /** Whether an assessment would raise this line. */
        public boolean isFinding() {
            return this == CONTRADICTED || this == EXCLUDED_WITHOUT_JUSTIFICATION || this == UNDECLARED;
        }
    }

    /**
     * @param declaration absent when {@code divergence} is {@link Divergence#UNDECLARED}
     * @param measured what the engine made of this control, or null when it evaluated none
     * @param reviewOverdue the line's own review has lapsed, whatever its divergence
     */
    public record Line(
            ComplianceControl control,
            Declaration declaration,
            ComplianceControl.Status measured,
            Divergence divergence,
            boolean reviewOverdue) {}

    /**
     * @param title the standard's own name — <b>{@code framework} alone is the Java constant</b>,
     *     and a screen showing {@code ISO_27001} or {@code EU_CRA} to an assessor is showing them
     *     an enum. The name has always existed on the framework; nothing carried it to the client
     * @param declared how many of the framework's controls the declaration addresses
     * @param findings lines an assessment would raise
     * @param complete every control is addressed — what clause 6.1.3 d asks for
     */
    public record SoaStatement(
            ComplianceFramework framework,
            String title,
            List<Line> lines,
            int total,
            int declared,
            int findings,
            int reviewsOverdue,
            boolean complete) {}

    /**
     * Sets one framework's declaration against its evaluation.
     *
     * <p>Driven by the <em>framework's</em> control list rather than by the declarations, so a
     * control nobody has written a line for appears as {@link Divergence#UNDECLARED} instead of
     * vanishing. A declaration naming a control the framework does not have is dropped: it
     * describes a revision of the standard this build does not carry, and inventing a row for it
     * would put a control in the document that the document's own framework denies.
     *
     * @param declarations by control id; duplicates are resolved by the last one seen
     */
    public static SoaStatement reconcile(
            ComplianceEvaluation evaluation, List<Declaration> declarations, Instant now) {

        Map<String, Declaration> byControl = declarations.stream()
                .filter(declaration -> declaration.framework().equals(evaluation.framework().name()))
                .collect(Collectors.toMap(
                        Declaration::controlId, Function.identity(), (first, second) -> second));

        Map<String, ComplianceControl.Status> measured = evaluation.controls().stream()
                .collect(Collectors.toMap(
                        assessment -> assessment.control().id(),
                        ComplianceEvaluation.ControlAssessment::status,
                        (first, second) -> second));

        List<Line> lines = new ArrayList<>();
        for (ComplianceControl control : evaluation.framework().getControls()) {
            Declaration declaration = byControl.get(control.id());
            ComplianceControl.Status status = measured.get(control.id());
            lines.add(new Line(
                    control,
                    declaration,
                    status,
                    diverge(declaration, status),
                    declaration != null && declaration.reviewOverdue(now)));
        }

        return new SoaStatement(
                evaluation.framework(),
                evaluation.framework().getTitle(),
                lines,
                lines.size(),
                (int) lines.stream().filter(line -> line.declaration() != null).count(),
                (int) lines.stream().filter(line -> line.divergence().isFinding()).count(),
                (int) lines.stream().filter(Line::reviewOverdue).count(),
                lines.stream().allMatch(line -> line.declaration() != null));
    }

    /**
     * The order of the tests below is the model.
     *
     * <p>Absence first, because an undeclared control cannot be anything else. Then exclusion,
     * which ends the question — an excluded control is not measured against, whatever the estate
     * happens to look like. Then evidence source, which decides whether the measurement is about
     * this claim at all. Only then do the two get compared.
     */
    private static Divergence diverge(Declaration declaration, ComplianceControl.Status measured) {
        if (declaration == null) {
            return Divergence.UNDECLARED;
        }
        if (declaration.applicability() == Applicability.EXCLUDED) {
            return isBlank(declaration.justification())
                    ? Divergence.EXCLUDED_WITHOUT_JUSTIFICATION
                    : Divergence.NOT_APPLICABLE;
        }
        if (declaration.evidenceSource() == EvidenceSource.EXTERNAL) {
            return Divergence.NOT_MEASURED_HERE;
        }
        if (measured == null || declaration.implementation() == null) {
            return Divergence.CONSISTENT;
        }
        return switch (declaration.implementation()) {
            case IMPLEMENTED -> switch (measured) {
                case NON_COMPLIANT -> Divergence.CONTRADICTED;
                case PARTIAL -> Divergence.OVERSTATED;
                case COMPLIANT -> Divergence.CONSISTENT;
            };
            case PLANNED, NOT_IMPLEMENTED -> measured == ComplianceControl.Status.COMPLIANT
                    ? Divergence.UNDERSTATED
                    : Divergence.CONSISTENT;
            case PARTIALLY_IMPLEMENTED -> Divergence.CONSISTENT;
        };
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
