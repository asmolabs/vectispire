package com.asmolabs.vectispire.core.checklists;

import com.asmolabs.vectispire.common.domain.checklists.Measurement;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistMeasurementEntity;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * What a rule found for one line, as the API shows it (decision 0032 §6): stored — relied on by an
 * answer, a submission or a sign-off — or computed for the reader and not stored, whose {@code id} is
 * null and {@code purpose} {@code read}.
 *
 * <p>The components are the entity's property names; {@code evidence} is its stored text read back,
 * typed, which is what {@code evidenceDigest} is the SHA-256 of.
 *
 * @param outcome {@code pass}, {@code fail} or {@code no_data} — no data is never a pass
 * @param reason for no data: {@code no_repository}, {@code never_examined}, {@code forge_unlinked}, {@code
 *     forge_unreadable}, {@code step_absent}, {@code
 *     language_not_analysed}, {@code examination_unrecorded}, {@code languages_unrecorded}, {@code
 *     packages_unrecorded}, {@code packages_not_kept}, {@code scope_matches_nothing}, {@code review_incomplete},
 *     {@code no_change_merged}, {@code stale}, {@code
 *     not_applicable_anywhere}, {@code suite_not_found}, {@code no_test_ran} — {@code NoDataReason}; null otherwise
 * @param asOf the oldest evidence the measurement rests on; null when it rests on none
 * @param boundRule the rule applied, as the line held it, in the shape a line's {@code rule} has — structured,
 *     like every other rule the API shows; {@code ruleDigest} is the SHA-256 of its stored canonical text
 * @param answerValue and {@code reconciliation}: the answer it was reconciled with at a submission or a
 *     sign-off, or the one resting on it, and what the two said together
 */
public record ChecklistMeasurementView(
        Long id,
        Long checklistId,
        Long itemId,
        String purpose,
        String ruleKind,
        String ruleDigest,
        ChecklistRuleForm boundRule,
        String outcome,
        String reason,
        Instant asOf,
        Instant computedAt,
        String computedBy,
        Long answerId,
        String answerValue,
        String reconciliation,
        String evidenceDigest,
        MeasurementEvidence evidence) {

    /** The evidence as judged: the summary, each repository's look, and the figures over the project. */
    public record MeasurementEvidence(String summary, List<RepositoryLook> repositories, List<MeasuredFigure> figures) {

        public MeasurementEvidence {
            repositories = List.copyOf(repositories);
            figures = List.copyOf(figures);
        }
    }

    /**
     * @param repositoryName the repository's name as every screen names it ({@code TargetNaming}) — null for
     *     one no longer in the project, or gone: the reader was judged by the project's repositories as they
     *     are, and a name is not handed out for one outside them, which a stored measurement may still cite
     * @param scope the scope's key for a findings rule, null for the other kinds
     * @param status {@code examined}, {@code not_applicable}, or the reason the repository has no data
     * @param source {@code scan}, {@code sarif_import}, {@code coverage_import}, {@code test_report_import};
     *     null when nothing was read
     * @param digest the SHA-256 of the document an import accepted; null for a scan
     * @param met whether the repository meets the rule's conditions; null where it has no data or the rule
     *     judges the project whole
     */
    public record RepositoryLook(long repositoryId, String repositoryName, String scope, String status, String source, Long sourceId,
            Instant at, String digest, Boolean met, String detail) {}

    /**
     * @param scope a scope's key, or {@code all} for the total a threshold was judged on
     * @param met whether its threshold holds; null where none applies or the data is incomplete
     */
    public record MeasuredFigure(String scope, String severity, long open, long resolved, Boolean met, String detail) {}

    /**
     * @param names the names of the repositories the reader may be told of, by identifier
     * @param rules the stored canonical text of a rule, read as its form
     */
    static ChecklistMeasurementView of(ChecklistMeasurementEntity row, Map<Long, String> names,
            Function<String, ChecklistRuleForm> rules) {
        return new ChecklistMeasurementView(row.getId(), row.getChecklistId(), row.getItemId(), row.getPurpose(),
                row.getRuleKind(), row.getRuleDigest(), rules.apply(row.getBoundRule()), row.getOutcome(), row.getReason(),
                row.getAsOf(), row.getComputedAt(), row.getComputedBy(), row.getAnswerId(), row.getAnswerValue(),
                row.getReconciliation(), row.getEvidenceDigest(), evidence(Measurement.read(row.getEvidence()), names));
    }

    static MeasurementEvidence evidence(Measurement measurement, Map<Long, String> names) {
        return new MeasurementEvidence(measurement.summary(),
                measurement.repositories().stream().map(line -> new RepositoryLook(line.repositoryId(),
                        names.get(line.repositoryId()), line.scope().orElse(null), line.status(),
                        line.look().map(look -> look.source().wireName()).orElse(null),
                        line.look().map(look -> look.id()).orElse(null),
                        line.look().map(look -> look.at()).orElse(null),
                        line.look().flatMap(look -> look.digest()).orElse(null),
                        line.met().orElse(null), line.detail().orElse(null))).toList(),
                measurement.figures().stream().map(figure -> new MeasuredFigure(figure.scope(), figure.severity(), figure.open(),
                        figure.resolved(), figure.met().orElse(null), figure.detail().orElse(null))).toList());
    }
}
