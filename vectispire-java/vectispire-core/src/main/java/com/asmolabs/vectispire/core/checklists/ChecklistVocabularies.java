package com.asmolabs.vectispire.core.checklists;

import com.asmolabs.vectispire.common.domain.checklists.ChecklistAnswer;
import com.asmolabs.vectispire.common.domain.checklists.ChecklistRule;
import com.asmolabs.vectispire.common.domain.checklists.EvidenceRequirement;
import com.asmolabs.vectispire.common.domain.checklists.Measurement;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementOutcome;
import com.asmolabs.vectispire.common.domain.checklists.NoDataReason;
import com.asmolabs.vectispire.common.domain.checklists.Reconciliation;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.media.Schema;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Stream;
import org.springdoc.core.customizers.OpenApiCustomizer;
import org.springframework.stereotype.Component;

/**
 * The closed vocabularies of the checklist views, enumerated in the OpenAPI document from the types
 * that write them.
 *
 * <p>The views carry their tokens as strings — the wire names the tables store — so the document said
 * {@code string} of each, and a generated client read an outcome, a status or a line's problem as any
 * text: the screen had to restate every list by hand, and nothing told it when the server added a
 * token. Enumerated here from the enums themselves rather than in {@code @Schema(allowableValues)}
 * literals beside each component, which would be a second list the constants can drift from.
 *
 * <p><b>A property named here that the document lacks fails the document</b>, rather than enumerating
 * nothing: a component renamed would otherwise quietly turn a union back into {@code string}, and
 * {@code ClientContractSpecTest} would record it as the contract.
 */
@Component
class ChecklistVocabularies implements OpenApiCustomizer {

    /** Schema, property, the tokens it takes — a list property's are its items'. */
    static Map<String, Map<String, List<String>>> vocabularies() {
        List<String> statuses = wire(ChecklistStatus.values(), ChecklistStatus::wireName);
        List<String> answers = wire(ChecklistAnswer.values(), ChecklistAnswer::wireName);
        List<String> outcomes = wire(MeasurementOutcome.values(), MeasurementOutcome::wireName);
        List<String> reasons = wire(NoDataReason.values(), NoDataReason::wireName);
        List<String> reconciliations = wire(Reconciliation.values(), Reconciliation::wireName);
        List<String> ruleKinds = wire(ChecklistRule.Kind.values(), ChecklistRule.Kind::wireName);
        List<String> evidenceKinds = wire(EvidenceRequirement.Kind.values(), EvidenceRequirement.Kind::wireName);
        List<String> lineProblems = wire(LineProblem.values(), LineProblem::wireName);

        Map<String, Map<String, List<String>>> table = new LinkedHashMap<>();
        table.put("ChecklistRevisionSummary", Map.of("status", statuses));
        table.put("ChecklistMeasurementsView", Map.of("status", statuses));
        table.put("ChecklistVersionSummary",
                Map.of("status", wire(TemplateVersionStatus.values(), TemplateVersionStatus::wireName)));
        table.put("ChecklistAnswerView", Map.of("value", answers));
        table.put("ChecklistEvidenceView", Map.of("kind", wire(ProofKind.values(), ProofKind::wireName)));
        table.put("ChecklistItemView", Map.of("evidenceKind", evidenceKinds));
        table.put("ChecklistLineView", Map.of("evidenceKind", evidenceKinds, "problems", lineProblems));
        table.put("ChecklistRuleForm", Map.of(
                "kind", ruleKinds,
                "metric", wire(ChecklistRule.Metric.values(), ChecklistRule.Metric::wireName),
                "aggregation", wire(ChecklistRule.Aggregation.values(), ChecklistRule.Aggregation::wireName)));
        table.put("ChecklistMeasurementView", Map.of(
                "purpose", wire(MeasurementPurpose.values(), MeasurementPurpose::wireName),
                "ruleKind", ruleKinds,
                "outcome", outcomes,
                "reason", reasons,
                "answerValue", answers,
                "reconciliation", reconciliations));
        table.put("MeasuredLineView", Map.of(
                "answer", answers,
                "reconciliation", reconciliations,
                // What a measurement adds to a line's problems — ProjectChecklistService.measurements.
                "problems", Stream.of(LineProblem.values())
                        .filter(problem -> problem == LineProblem.MEASUREMENT_CONTRADICTED || problem.askedWhereNoData())
                        .map(LineProblem::wireName).toList()));
        // The act gives a "yes" on a passing measurement, never anything else — ProjectChecklistService.answerAsMeasured.
        table.put("AsMeasuredAnswer", Map.of("value", List.of(ChecklistAnswer.YES.wireName())));
        table.put("AsMeasuredSkip", Map.of(
                "reason", wire(AsMeasuredSkipReason.values(), AsMeasuredSkipReason::wireName),
                "outcome", outcomes,
                "noDataReason", reasons,
                "answer", answers));
        table.put("RepositoryLook", Map.of(
                "status", Stream.concat(
                        Stream.of(Measurement.RepositoryEvidence.EXAMINED, Measurement.RepositoryEvidence.NOT_APPLICABLE),
                        reasons.stream()).toList(),
                "source", wire(MeasurementFacts.Source.values(), MeasurementFacts.Source::wireName)));
        table.put("MeasuredFigure", Map.of("severity", wire(Severity.values(), Severity::wireName)));
        // The problem's lines member: a contradiction has a refusal of its own, so an incomplete line
        // never names one.
        table.put("IncompleteLine", Map.of("problems", Stream.of(LineProblem.values())
                .filter(problem -> problem != LineProblem.MEASUREMENT_CONTRADICTED)
                .map(LineProblem::wireName).toList()));
        table.put("MeasuredLine", Map.of(
                "answer", answers,
                "outcome", outcomes,
                "reason", reasons,
                "submittedOutcome", outcomes,
                "submittedReason", reasons));
        return table;
    }

    @Override
    @SuppressWarnings("rawtypes") // the document's own map of components is raw
    public void customise(OpenAPI document) {
        Map<String, Schema> schemas = document.getComponents() == null ? null : document.getComponents().getSchemas();
        vocabularies().forEach((name, properties) -> properties.forEach((property, tokens) -> {
            Schema<?> owner = schemas == null ? null : schemas.get(name);
            Schema<?> field = owner == null || owner.getProperties() == null ? null : owner.getProperties().get(property);
            if (field == null) {
                throw new IllegalStateException("The OpenAPI document has no " + name + "." + property
                        + " to enumerate: a checklist view was renamed without its vocabulary.");
            }
            enumerate(field.getItems() != null ? field.getItems() : field, tokens);
        }));
    }

    @SuppressWarnings("unchecked")
    private static void enumerate(Schema<?> field, List<String> tokens) {
        ((Schema<Object>) field).setEnum(new ArrayList<>(tokens));
    }

    private static <E> List<String> wire(E[] values, Function<E, String> wireName) {
        return Arrays.stream(values).map(wireName).toList();
    }
}
