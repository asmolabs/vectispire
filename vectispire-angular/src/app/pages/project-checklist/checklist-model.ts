import type {
    AsMeasuredSkipReason,
    ChecklistAnswer,
    ChecklistAnswerValue,
    ChecklistAsMeasuredSkip,
    ChecklistEvidenceKind,
    ChecklistIncompleteLine,
    ChecklistLine,
    ChecklistLineProblem,
    ChecklistStatus,
    ChecklistView
} from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { keyFor } from '../../core/i18n/literal-keys';
import { NO_DATA_SHORT_KEYS, OUTCOME_KEYS } from './measurements';

/*
 * The project checklist's words and judgements, shared by the page and the components it is made of:
 * literal keys for every value the server sends, the refusals it names by type, and the pure helpers
 * that read its answers. Nothing here holds state or reaches the server — that is `ChecklistPage`.
 */

/**
 * Whether Vectispire wrote this answer from a measurement (decision 0032, amendment of 2026-09-29).
 * Decided by the kind and never by the name: `answeredBy` reads "Vectispire" on a system row, and an
 * account may be called that too — usernames are free text. An absent kind is a person's: every row
 * written before the amendment was one.
 */
export function isAutomatic(answer: Pick<ChecklistAnswer, 'answeredByKind'> | null | undefined): boolean {
    return answer?.answeredByKind === 'system';
}

// Literal keys, so the i18n check sees each value's translation and a new one cannot ship as a raw
// key (decision 0019). The check counts none of these — they are not `t('…')` calls — so the spec
// reads each against both bundles.
export const STATUS_KEYS = {
    draft: 'project_checklist.status_draft',
    submitted: 'project_checklist.status_submitted',
    signed_off: 'project_checklist.status_signed_off',
    superseded: 'project_checklist.status_superseded'
} as const satisfies Record<ChecklistStatus, string>;

export const ANSWER_KEYS = {
    yes: 'project_checklist.answer_yes',
    no: 'project_checklist.answer_no',
    not_applicable: 'project_checklist.answer_not_applicable'
} as const satisfies Record<ChecklistAnswerValue, string>;

export const PROBLEM_KEYS = {
    unanswered: 'project_checklist.problem_unanswered',
    awaiting_confirmation: 'project_checklist.problem_awaiting_confirmation',
    measurement_contradicted: 'project_checklist.measured_problem_contradicted',
    comment_required: 'project_checklist.problem_comment_required',
    evidence_required: 'project_checklist.problem_evidence_required',
    evidence_expired: 'project_checklist.problem_evidence_expired'
} as const satisfies Record<ChecklistLineProblem, string>;

export const EVIDENCE_KIND_KEYS = {
    none: 'project_checklist.evidence_kind_none',
    link_or_file: 'project_checklist.evidence_kind_link_or_file',
    file: 'project_checklist.evidence_kind_file'
} as const satisfies Record<ChecklistEvidenceKind, string>;

/**
 * Why the server refused a checklist write for the state it found: `ChecklistConflict.Cause`, read
 * from the problem's `type` — never from its English `detail`, whose wording is free to change.
 */
export type ConflictCause =
    | 'changed'
    | 'line_changed'
    | 'not_draft'
    | 'not_submitted'
    | 'not_signed_off'
    | 'not_latest'
    | 'incomplete'
    | 'four_eyes'
    | 'version_not_published'
    | 'same_version'
    | 'version_unrenderable'
    | 'nothing_to_confirm'
    | 'evidence_withdrawn'
    | 'measurement_contradicted'
    | 'measurement_changed';

/** `ApiExceptionHandler.PROBLEM_TYPE` followed by `Cause.token()`, one per cause. */
export const CONFLICT_TYPES: Readonly<Record<string, ConflictCause>> = {
    'urn:vectispire:problem:checklist-changed': 'changed',
    'urn:vectispire:problem:checklist-line-changed': 'line_changed',
    'urn:vectispire:problem:checklist-not-draft': 'not_draft',
    'urn:vectispire:problem:checklist-not-submitted': 'not_submitted',
    'urn:vectispire:problem:checklist-not-signed-off': 'not_signed_off',
    'urn:vectispire:problem:checklist-not-latest': 'not_latest',
    'urn:vectispire:problem:checklist-incomplete': 'incomplete',
    'urn:vectispire:problem:checklist-four-eyes': 'four_eyes',
    'urn:vectispire:problem:checklist-version-not-published': 'version_not_published',
    'urn:vectispire:problem:checklist-same-version': 'same_version',
    'urn:vectispire:problem:checklist-version-unrenderable': 'version_unrenderable',
    'urn:vectispire:problem:checklist-nothing-to-confirm': 'nothing_to_confirm',
    'urn:vectispire:problem:checklist-evidence-withdrawn': 'evidence_withdrawn',
    'urn:vectispire:problem:checklist-measurement-contradicted': 'measurement_contradicted',
    'urn:vectispire:problem:checklist-measurement-changed': 'measurement_changed'
};

export const CONFLICT_KEYS = {
    changed: 'project_checklist.conflict_changed',
    line_changed: 'project_checklist.conflict_line_changed',
    not_draft: 'project_checklist.conflict_not_draft',
    not_submitted: 'project_checklist.conflict_not_submitted',
    not_signed_off: 'project_checklist.conflict_not_signed_off',
    not_latest: 'project_checklist.conflict_not_latest',
    incomplete: 'project_checklist.conflict_incomplete',
    four_eyes: 'project_checklist.conflict_four_eyes',
    version_not_published: 'project_checklist.conflict_version_not_published',
    same_version: 'project_checklist.conflict_same_version',
    version_unrenderable: 'project_checklist.conflict_version_unrenderable',
    nothing_to_confirm: 'project_checklist.conflict_nothing_to_confirm',
    evidence_withdrawn: 'project_checklist.conflict_evidence_withdrawn',
    measurement_contradicted: 'project_checklist.conflict_measurement_contradicted',
    measurement_changed: 'project_checklist.conflict_measurement_changed'
} as const satisfies Record<ConflictCause, string>;

/**
 * The reasons the as-measured act's summary names, in the order a person deals with them: the no they
 * owe first. `already_answered` is named only for a line the screen sent — every line answered before
 * is also reported, and listing them would bury what the act did.
 */
export const AS_MEASURED_SKIP_KEYS = {
    needs_comment: 'project_checklist.as_measured_needs_comment',
    measurement_changed: 'project_checklist.as_measured_changed',
    not_shown: 'project_checklist.as_measured_not_shown',
    no_data: 'project_checklist.as_measured_no_data',
    already_answered: 'project_checklist.as_measured_already_answered'
} as const satisfies Record<AsMeasuredSkipReason, string>;

/** One reason of the summary with the lines it left alone, by position. */
export interface AsMeasuredGroup {
    reason: AsMeasuredSkipReason;
    lines: { itemId: number; position: number }[];
}

/** What the last as-measured act did, for the summary: kept until another revision is read. */
export interface AsMeasuredSummary {
    revision: number;
    answered: number;
    sent: ReadonlySet<number>;
    skipped: ChecklistAsMeasuredSkip[];
}

/** Why the sign-off is greyed out for the person on screen — a hint: the server decides. */
export type SignOffBlock = 'not_approver' | 'four_eyes';

/** The platform's public key, the one the document's signatures are checked against (decision 0032 §10). */
export const PUBLIC_KEY_PATH = '/api/v1/crypto/public-key.pub';
/** The name the server's `Content-Disposition` gives the key, which the commands use and the link repeats. */
export const PUBLIC_KEY_FILE = 'vectispire-signing-key.pub';

/** A refusal explained, whether reloading is what it asks for, and the line it concerns, if one. */
export interface Refusal {
    message: string;
    reload: boolean;
    itemId: number | null;
}

/** The answer being written on one line. */
export interface AnswerDraft {
    itemId: number;
    value: ChecklistAnswerValue | null;
    comment: string;
    /**
     * The measurement the form was opened from, by its evidence digest and the answer it offered: sent
     * only while that answer is the one chosen — another answer rests on no measurement.
     */
    restingOn: { digest: string; value: ChecklistAnswerValue; computedAt: string } | null;
}

/** The proof being attached to one line. */
export interface EvidenceDraft {
    itemId: number;
    kind: 'link' | 'file';
    link: string;
    file: File | null;
    performedOn: string;
}

/** A domain of the checklist, its objectives in the template's order, each with its lines. */
export interface DomainGroup {
    domain: string | null;
    objectives: { objective: string | null; lines: ChecklistLine[] }[];
}

// ---------------------------------------------------------------------- pure helpers

export const DAY = /^\d{4}-\d{2}-\d{2}$/;
/** What the server accepts as a link proof: `https:` or `http:` with a host. It checks again. */
export const LINK = /^https?:\/\/[^\s/?#]+/i;

/** The cause a checklist refusal names in its problem type, or `null` for any other refusal. */
export function conflictOf(failure: unknown): ConflictCause | null {
    const type = (failure as { error?: { type?: unknown } } | null)?.error?.type;
    return typeof type === 'string' ? (CONFLICT_TYPES[type] ?? null) : null;
}

/**
 * The lines a `checklist-incomplete` refusal names in its `lines` member, or `null` when it names
 * none the screen can read — a server from before the member, or a shape it does not expect — so that
 * the caller falls back to the lines the view shows.
 */
export function incompleteLinesOf(failure: unknown): ChecklistIncompleteLine[] | null {
    const lines = (failure as { error?: { lines?: unknown } } | null)?.error?.lines;
    if (!Array.isArray(lines)) return null;
    const read = lines.filter(
        (line): line is ChecklistIncompleteLine =>
            typeof (line as ChecklistIncompleteLine | null)?.itemId === 'number' &&
            typeof (line as ChecklistIncompleteLine).position === 'number' &&
            Array.isArray((line as ChecklistIncompleteLine).problems) &&
            (line as ChecklistIncompleteLine).problems.every((problem) => typeof problem === 'string')
    );
    return read.length > 0 ? read : null;
}

/**
 * Lines grouped by domain, then by objective, each in the order its first line appears — the
 * template's own order, which the positions carry.
 */
export function groupsOf(lines: ChecklistLine[]): DomainGroup[] {
    const groups: DomainGroup[] = [];
    for (const line of [...lines].sort((a, b) => a.position - b.position)) {
        let group = groups.find((one) => one.domain === line.domain);
        if (!group) {
            group = { domain: line.domain, objectives: [] };
            groups.push(group);
        }
        let objective = group.objectives.find((one) => one.objective === line.objective);
        if (!objective) {
            objective = { objective: line.objective, lines: [] };
            group.objectives.push(objective);
        }
        objective.lines.push(line);
    }
    return groups;
}

/**
 * Why the person on screen may not sign this revision off, if they may not: not an approver, or,
 * under four-eyes, one of its authors — compared by name without case, the side of the server's
 * comparison the screen can make.
 */
export function signOffBlockOf(
    view: ChecklistView | null,
    approves: boolean,
    username: string | null | undefined
): SignOffBlock | null {
    if (!approves) return 'not_approver';
    const me = username?.trim().toLowerCase();
    if (view?.fourEyesRequired && !!me && view.authors.some((author) => author.trim().toLowerCase() === me)) {
        return 'four_eyes';
    }
    return null;
}

export function parseChoice(choice: string | null): { slug: string; ordinal: number } | null {
    if (!choice) return null;
    const at = choice.lastIndexOf(':');
    const ordinal = Number(choice.slice(at + 1));
    return at > 0 && Number.isInteger(ordinal) ? { slug: choice.slice(0, at), ordinal } : null;
}

/** Today as the server reads a proof's day — in UTC, so that a day it calls future is not offered. */
export function todayUtc(): string {
    return new Date().toISOString().slice(0, 10);
}

// ---------------------------------------------------------------------- labels

/** A status in words; one the client does not know is shown as sent. */
export function statusLabel(i18n: I18nService, status: string): string {
    const key = keyFor(STATUS_KEYS, status);
    return key ? i18n.t(key) : status;
}

export function statusSeverity(status: string): 'warn' | 'info' | 'success' | 'secondary' {
    return status === 'draft'
        ? 'warn'
        : status === 'submitted'
          ? 'info'
          : status === 'signed_off'
            ? 'success'
            : 'secondary';
}

export function answerLabel(i18n: I18nService, value: string): string {
    const key = keyFor(ANSWER_KEYS, value);
    return key ? i18n.t(key) : value;
}

export function problemLabel(i18n: I18nService, problem: string): string {
    const key = keyFor(PROBLEM_KEYS, problem);
    return key ? i18n.t(key) : problem;
}

export function evidenceKindLabel(i18n: I18nService, kind: string): string {
    const key = keyFor(EVIDENCE_KIND_KEYS, kind);
    return key ? i18n.t(key) : kind;
}

/**
 * Who an answer is by, as the screen names it: a system row is Vectispire's in the product's words,
 * whatever its `answeredBy` says, so that it never reads as a person's.
 */
export function authorOf(i18n: I18nService, answer: Pick<ChecklistAnswer, 'answeredBy' | 'answeredByKind'>): string {
    return isAutomatic(answer) ? i18n.t('project_checklist.system_author') : answer.answeredBy;
}

/** "Not met", or "No data (never examined)": what a refused line's measurement says, in words. */
export function measuredWords(i18n: I18nService, outcome: string | null, reason: string | null): string {
    const outcomeKey = outcome ? keyFor(OUTCOME_KEYS, outcome) : undefined;
    const said = outcomeKey ? i18n.t(outcomeKey) : '—';
    const reasonKey = reason ? keyFor(NO_DATA_SHORT_KEYS, reason) : undefined;
    const short = reasonKey ? i18n.t(reasonKey) : '';
    return short ? `${said} (${short})` : said;
}

/**
 * Whether the revision's document is called signed. **Only its status can say so**: a signed-off
 * revision's package was signed at its sign-off — except one signed off before documents were, which
 * the server renders unsigned and the screen cannot tell apart. So the screen says "signed package"
 * for a signed-off revision and nothing stronger, and the guide names the exception.
 */
export function documentSigned(status: string): boolean {
    return status === 'signed_off';
}
