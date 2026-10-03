import type {
    ChecklistAnswerValue,
    ChecklistMeasuredConflictLine,
    ChecklistMeasurements,
    MeasuredLine,
    MeasuredLineProblem,
    MeasurementOutcome,
    MeasurementSource,
    NoDataReason,
    Reconciliation
} from '../../core/api.models';

/**
 * A project checklist's measured lines in words (decision 0032 §6), and the few judgements the screen
 * makes from them — each one a hint the server repeats: it measures again at the submission and at the
 * sign-off, and refuses in its own right.
 *
 * Literal keys, so that a new value cannot ship as a raw key (decision 0019); the i18n check counts
 * none of them, so the spec reads each against both bundles.
 */

export const OUTCOME_KEYS = {
    pass: 'project_checklist.outcome_pass',
    fail: 'project_checklist.outcome_fail',
    no_data: 'project_checklist.outcome_no_data'
} as const satisfies Record<MeasurementOutcome, string>;

/** Why there is no data, in a sentence: the product saying it did not look, never that it found nothing. */
export const NO_DATA_KEYS = {
    no_repository: 'project_checklist.reason_no_repository',
    never_examined: 'project_checklist.reason_never_examined',
    step_absent: 'project_checklist.reason_step_absent',
    plugin_unsigned: 'project_checklist.reason_plugin_unsigned',
    plugin_signature_unverified: 'project_checklist.reason_plugin_signature_unverified',
    plugin_registry_authentication_required: 'project_checklist.reason_plugin_registry_authentication_required',
    language_not_analysed: 'project_checklist.reason_language_not_analysed',
    examination_unrecorded: 'project_checklist.reason_examination_unrecorded',
    languages_unrecorded: 'project_checklist.reason_languages_unrecorded',
    version_unrecorded: 'project_checklist.reason_version_unrecorded',
    packages_unrecorded: 'project_checklist.reason_packages_unrecorded',
    packages_not_kept: 'project_checklist.reason_packages_not_kept',
    scope_matches_nothing: 'project_checklist.reason_scope_matches_nothing',
    stale: 'project_checklist.reason_stale',
    not_applicable_anywhere: 'project_checklist.reason_not_applicable_anywhere',
    suite_not_found: 'project_checklist.reason_suite_not_found',
    no_test_ran: 'project_checklist.reason_no_test_ran'
} as const satisfies Record<NoDataReason, string>;

/** The same reasons in a word or two, where a repository's row or a refusal names one. */
export const NO_DATA_SHORT_KEYS = {
    no_repository: 'project_checklist.reason_short_no_repository',
    never_examined: 'project_checklist.reason_short_never_examined',
    step_absent: 'project_checklist.reason_short_step_absent',
    plugin_unsigned: 'project_checklist.reason_short_plugin_unsigned',
    plugin_signature_unverified: 'project_checklist.reason_short_plugin_signature_unverified',
    plugin_registry_authentication_required: 'project_checklist.reason_short_plugin_registry_authentication_required',
    language_not_analysed: 'project_checklist.reason_short_language_not_analysed',
    examination_unrecorded: 'project_checklist.reason_short_examination_unrecorded',
    languages_unrecorded: 'project_checklist.reason_short_languages_unrecorded',
    version_unrecorded: 'project_checklist.reason_short_version_unrecorded',
    packages_unrecorded: 'project_checklist.reason_short_packages_unrecorded',
    packages_not_kept: 'project_checklist.reason_short_packages_not_kept',
    scope_matches_nothing: 'project_checklist.reason_short_scope_matches_nothing',
    stale: 'project_checklist.reason_short_stale',
    not_applicable_anywhere: 'project_checklist.reason_short_not_applicable_anywhere',
    suite_not_found: 'project_checklist.reason_short_suite_not_found',
    no_test_ran: 'project_checklist.reason_short_no_test_ran'
} as const satisfies Record<NoDataReason, string>;

/** A repository's status in the evidence: examined, left out because the plugin does not apply, or a reason. */
export const LOOK_STATUS_KEYS = {
    examined: 'project_checklist.look_examined',
    not_applicable: 'project_checklist.look_not_applicable',
    ...NO_DATA_SHORT_KEYS
} as const;

export const SOURCE_KEYS = {
    scan: 'project_checklist.source_scan',
    sarif_import: 'project_checklist.source_sarif_import',
    coverage_import: 'project_checklist.source_coverage_import',
    test_report_import: 'project_checklist.source_test_report_import'
} as const satisfies Record<MeasurementSource, string>;

/** The statement of applicability's vocabulary: what the answer and the measurement say together. */
export const RECONCILIATION_KEYS = {
    consistent: 'project_checklist.reconciliation_consistent',
    contradicted: 'project_checklist.reconciliation_contradicted',
    declared_not_measured: 'project_checklist.reconciliation_declared_not_measured',
    understated: 'project_checklist.reconciliation_understated',
    excluded: 'project_checklist.reconciliation_excluded',
    not_measured_here: 'project_checklist.reconciliation_not_measured_here',
    unanswered: 'project_checklist.reconciliation_unanswered'
} as const satisfies Record<Reconciliation, string>;

export const RECONCILIATION_SEVERITIES = {
    consistent: 'success',
    contradicted: 'danger',
    declared_not_measured: 'warn',
    understated: 'info',
    excluded: 'secondary',
    not_measured_here: 'secondary',
    unanswered: 'secondary'
} as const satisfies Record<Reconciliation, 'success' | 'danger' | 'warn' | 'info' | 'secondary'>;

/**
 * What the measurement keeps from a submission, in its own words. On a draft the checklist view's line
 * problems and `readyToSubmit` count these too; the badge only says what the line does not already.
 */
export const MEASURED_PROBLEM_KEYS = {
    measurement_contradicted: 'project_checklist.measured_problem_contradicted',
    comment_required: 'project_checklist.measured_problem_comment_required',
    evidence_required: 'project_checklist.measured_problem_evidence_required',
    evidence_expired: 'project_checklist.measured_problem_evidence_expired'
} as const satisfies Record<MeasuredLineProblem, string>;

/**
 * The answer a measurement offers in one click: yes where it is met, no where it is not — and nothing
 * where there is no data, since a measurement that did not look offers no answer to rest on.
 */
export function measuredAnswer(line: MeasuredLine | null | undefined): ChecklistAnswerValue | null {
    const outcome = line?.measurement?.outcome;
    return outcome === 'pass' ? 'yes' : outcome === 'fail' ? 'no' : null;
}

/**
 * The answer the one click offers on a line, or null where it offers none: only on live measurements
 * (a frozen one is read, not answered), to a person who may answer now. The line's button and the
 * page's "every measured line" act read it here, so the act sends exactly the lines a button showed.
 */
export function oneClickAnswer(
    line: MeasuredLine | null | undefined,
    live: boolean,
    answerable: boolean
): ChecklistAnswerValue | null {
    return live && answerable ? measuredAnswer(line) : null;
}

/**
 * The lines of a submitted revision whose measurement is not what the submission stored — outcome or
 * reason, as the sign-off compares them — by position: the sign-off would be refused for them.
 */
export function changedSinceSubmission(measurements: ChecklistMeasurements | null): number[] {
    if (!measurements?.live || measurements.status !== 'submitted') return [];
    return measurements.lines
        .filter((line) => line.measurement && line.atSubmission && differs(line))
        .map((line) => line.position)
        .sort((a, b) => a - b);
}

export function differs(line: MeasuredLine): boolean {
    const now = line.measurement;
    const then = line.atSubmission;
    return !!now && !!then && (now.outcome !== then.outcome || (now.reason ?? null) !== (then.reason ?? null));
}

/**
 * The lines a `checklist-measurement-contradicted` or `checklist-measurement-changed` refusal names in
 * its `lines` member, or `null` when it names none the screen can read.
 */
export function measuredConflictLinesOf(failure: unknown): ChecklistMeasuredConflictLine[] | null {
    const lines = (failure as { error?: { lines?: unknown } } | null)?.error?.lines;
    if (!Array.isArray(lines)) return null;
    const read = lines.filter(
        (line): line is ChecklistMeasuredConflictLine =>
            typeof (line as ChecklistMeasuredConflictLine | null)?.itemId === 'number' &&
            typeof (line as ChecklistMeasuredConflictLine).position === 'number' &&
            typeof (line as ChecklistMeasuredConflictLine).outcome === 'string'
    );
    return read.length > 0 ? read : null;
}
