import { DatePipe, NgTemplateOutlet } from '@angular/common';
import { HttpHeaders } from '@angular/common/http';
import {
    afterNextRender,
    ChangeDetectionStrategy,
    Component,
    computed,
    effect,
    inject,
    Injector,
    input,
    signal,
    untracked
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { forkJoin, type Observable } from 'rxjs';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { TextareaModule } from '@openng/optimus-ui/textarea';
import { messageOf } from '../../core/api-error';
import { ChecklistsApi, MAX_EVIDENCE_BYTES } from '../../core/api/checklists.api';
import type {
    AsMeasuredSkipReason,
    ChecklistAnswer,
    ChecklistAnswerValue,
    ChecklistAsMeasured,
    ChecklistAsMeasuredSkip,
    ChecklistEvidence,
    ChecklistEvidenceKind,
    ChecklistIncompleteLine,
    ChecklistLine,
    ChecklistLineHistory,
    ChecklistLineProblem,
    ChecklistMeasuredConflictLine,
    ChecklistMeasurements,
    ChecklistOfferedVersion,
    ChecklistProjectContext,
    ChecklistRevisionSummary,
    ChecklistShownMeasurement,
    ChecklistStatus,
    ChecklistView,
    MeasuredLine
} from '../../core/api.models';
import { saveDocument } from '../../core/download';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { LatestRequest } from '../../core/latest-request';
import { SessionStore } from '../../core/session.store';
import { describeUnrenderableCells, unrenderableCellsOf } from '../../shared/unrenderable-cells';
import { LineMeasurement } from './line-measurement';
import {
    changedSinceSubmission,
    measuredAnswer,
    measuredConflictLinesOf,
    NO_DATA_SHORT_KEYS,
    oneClickAnswer,
    OUTCOME_KEYS
} from './measurements';

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
interface AsMeasuredSummary {
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
interface Refusal {
    message: string;
    reload: boolean;
    itemId: number | null;
}

/** The answer being written on one line. */
interface AnswerDraft {
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
interface EvidenceDraft {
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

/**
 * A project's security checklist (decision 0032 §4, §5, §8), answered by people.
 *
 * **Read by whoever sees the whole project, and by nobody else.** The server answers 404 to a
 * reader who sees part of it — the words of an absent project — and the screen says exactly that,
 * without guessing which of the two it is.
 *
 * **Every write names the edition on screen, and adopts the checklist it gets back.** The edition
 * moves on at every write, so the view each write returns replaces the one shown; a write from a
 * stale screen is refused by the server (409), and the refusal is explained from the problem's
 * `type` — a changed line, a changed checklist, the four-eyes rule — with a reload offered where
 * reloading is the remedy.
 *
 * **Writes are offered to the roles that cause effects** (`@RequiresWriteAccount`); the auditor and
 * the platform governor read. The sign-off is an approver's and, under four-eyes, somebody who wrote
 * none of the revision: the button says why it is greyed out, from the `authors` and
 * `fourEyesRequired` the view carries, and the server has the last word.
 */
@Component({
    selector: 'app-project-checklist',
    imports: [
        DatePipe,
        NgTemplateOutlet,
        FormsModule,
        RouterLink,
        ButtonModule,
        CardModule,
        InputTextModule,
        MessageModule,
        TableModule,
        TagModule,
        TextareaModule,
        TranslatePipe,
        LineMeasurement
    ],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './project-checklist.html'
})
export class ProjectChecklist {
    private readonly api = inject(ChecklistsApi);
    private readonly i18n = inject(I18nService);
    private readonly session = inject(SessionStore);
    private readonly injector = inject(Injector);
    // The revision shown can be switched faster than the server answers; the older answer must not
    // land over the newer one.
    private readonly readRequest = new LatestRequest();
    // The measurements are read again after every write; an older answer must not land over a newer one.
    private readonly measureRequest = new LatestRequest();

    /** The route's `:projectId`, bound by `withComponentInputBinding`. */
    readonly projectId = input.required<string>();
    readonly id = computed(() => Number(this.projectId()));

    readonly maxEvidenceBytes = MAX_EVIDENCE_BYTES;
    readonly answerValues: readonly ChecklistAnswerValue[] = ['yes', 'no', 'not_applicable'];

    /** `@RequiresWriteAccount`: open, answer, prove, submit, return, reopen, move. */
    readonly writes = this.session.canCauseEffects;
    /** `canApproveTriage`: who may sign off at all. */
    readonly approves = this.session.canApproveTriage;

    readonly context = signal<ChecklistProjectContext | null>(null);
    readonly revisions = signal<ChecklistRevisionSummary[]>([]);
    readonly view = signal<ChecklistView | null>(null);
    /**
     * The lines a `checklist-incomplete` refusal named, by item, with their problems as the server
     * found them — which may not be what the view on screen says: a proof lapses without a write.
     */
    readonly incomplete = signal<Record<number, ChecklistLineProblem[]>>({});
    readonly offered = signal<ChecklistOfferedVersion[]>([]);
    readonly loading = signal(true);
    readonly notFound = signal(false);
    readonly error = signal<string | null>(null);
    readonly notice = signal<string | null>(null);
    readonly refusal = signal<Refusal | null>(null);
    readonly busy = signal(false);

    readonly openChoice = signal<string | null>(null);
    readonly moveChoice = signal<string | null>(null);
    readonly answering = signal<AnswerDraft | null>(null);
    readonly answerError = signal<string | null>(null);
    readonly proving = signal<EvidenceDraft | null>(null);
    readonly evidenceError = signal<string | null>(null);
    readonly returning = signal(false);
    readonly returnReason = signal('');
    readonly returnError = signal<string | null>(null);
    /** The histories open, by line; `null` while one is being read. */
    readonly histories = signal<Record<number, ChecklistLineHistory | null>>({});
    /** The revision's measured lines; null until read, and while the revision has none bound. */
    readonly measurements = signal<ChecklistMeasurements | null>(null);
    readonly measurementsError = signal<string | null>(null);
    /**
     * The lines a measurement refusal named — `checklist-measurement-contradicted` at a submission,
     * `checklist-measurement-changed` at a sign-off or an answer — by item, as the server found them.
     */
    readonly measuredConflicts = signal<Record<number, ChecklistMeasuredConflictLine>>({});
    /** The last "every measured line" act's summary, or null. */
    readonly asMeasured = signal<AsMeasuredSummary | null>(null);
    /** The revision whose document is being fetched, if one. */
    readonly downloading = signal<number | null>(null);
    readonly copied = signal(false);
    /** Served to anybody, so the link works on its own — no session, no request of the page. */
    readonly publicKeyPath = PUBLIC_KEY_PATH;
    readonly publicKeyFile = PUBLIC_KEY_FILE;

    /** Named before any checklist exists, from the context; from the view only if the context is not read yet. */
    readonly projectName = computed(() => this.context()?.projectName ?? this.view()?.projectName ?? null);
    readonly summary = computed(() => this.view()?.checklist ?? null);
    readonly latest = computed(() => this.revisions()[0] ?? null);
    readonly isLatest = computed(() => {
        const shown = this.summary();
        return !!shown && shown.revision === this.latest()?.revision;
    });
    readonly status = computed(() => this.summary()?.status ?? null);
    /** Lines are answered and proven on the newest revision while it is a draft, by those who write. */
    readonly editable = computed(() => this.writes() && this.isLatest() && this.status() === 'draft');
    readonly groups = computed(() => groupsOf(this.view()?.lines ?? []));
    readonly unready = computed(() =>
        (this.view()?.lines ?? []).filter((line) => line.problems.length > 0).map((line) => line.position)
    );
    readonly signOffBlock = computed<SignOffBlock | null>(() =>
        signOffBlockOf(this.view(), this.approves(), this.session.user()?.username)
    );
    readonly openOptions = computed(() => this.offered().map((version) => this.option(version)));
    /** Every published version but the one the checklist is on: moving to it again is refused. */
    readonly moveOptions = computed(() => {
        const shown = this.summary();
        return this.offered()
            .filter(
                (version) =>
                    !shown || version.templateSlug !== shown.templateSlug || version.ordinal !== shown.versionOrdinal
            )
            .map((version) => this.option(version));
    });
    readonly today = todayUtc();

    /** Whether any line of the revision is bound to a rule: only then are the measurements read. */
    readonly measured = computed(() => (this.view()?.lines ?? []).some((line) => !!line.rule));
    /** Lines whose current answer Vectispire wrote: what the scans filled, at a glance in the header. */
    readonly automaticCount = computed(
        () => (this.view()?.lines ?? []).filter((line) => isAutomatic(line.answer)).length
    );
    readonly measuredLines = computed(
        () => new Map((this.measurements()?.lines ?? []).map((line) => [line.itemId, line] as const))
    );
    /**
     * The view's own verdict: on a draft its `readyToSubmit` and line problems already count what the
     * submission's measurement would refuse — a yes the measurement contradicts, a yes without data short
     * of its comment or proof — so the measurements route is read to show them, never to decide.
     */
    readonly canSubmit = computed(() => !!this.view()?.readyToSubmit);
    /** Lines measured otherwise than at the submission: the sign-off would be refused for them. */
    readonly changedSinceSubmission = computed(() => changedSinceSubmission(this.measurements()));
    /**
     * The lines "every measured line" sends: each unanswered line whose own button offers the one click,
     * with the digest of the measurement that button would rest on — `oneClickAnswer`, the button's own
     * test, so the act never names a line the person was not shown as answerable. A not-met line is sent
     * too: the server leaves it for the person's no, and the summary names it.
     */
    readonly asMeasuredOffer = computed<ChecklistShownMeasurement[]>(() => {
        const live = !!this.measurements()?.live;
        const answerable = this.editable();
        return (this.view()?.lines ?? []).flatMap((line) => {
            const measured = this.measuredOf(line);
            const found = measured?.measurement;
            return !line.answer && found && oneClickAnswer(measured, live, answerable)
                ? [{ itemId: line.itemId, measurementDigest: found.evidenceDigest }]
                : [];
        });
    });
    /**
     * The summary's groups, against the view as it now is: a line answered since — the no a
     * `needs_comment` line was waiting for — leaves its group, so the summary is a list to work through.
     */
    readonly asMeasuredGroups = computed<AsMeasuredGroup[]>(() => {
        const summary = this.asMeasured();
        if (!summary) return [];
        const answered = new Set((this.view()?.lines ?? []).filter((line) => !!line.answer).map((line) => line.itemId));
        return (Object.keys(AS_MEASURED_SKIP_KEYS) as AsMeasuredSkipReason[])
            .map((reason) => ({
                reason,
                lines: summary.skipped
                    .filter((skip) => skip.reason === reason)
                    .filter((skip) =>
                        reason === 'already_answered' ? summary.sent.has(skip.itemId) : !answered.has(skip.itemId)
                    )
                    .map((skip) => ({ itemId: skip.itemId, position: skip.position }))
                    .sort((a, b) => a.position - b.position)
            }))
            .filter((group) => group.lines.length > 0);
    });

    constructor() {
        // An effect rather than a call in the constructor: a signal input is not bound yet there.
        effect(() => {
            const id = this.id();
            untracked(() => this.load(id));
        });
    }

    // ------------------------------------------------------------------ reading

    /** Everything read again, the newest revision shown — what a refusal for a stale screen asks for. */
    reload(): void {
        this.load(this.id());
    }

    /**
     * The context and the revisions, read together. **The context decides whether there is a
     * checklist to show**, not the list: it is the read whose edition an opening names, so the page
     * that offers to open one is the page that saw none there — a checklist opened between the two
     * reads is then refused by the server rather than moved onto, unseen.
     */
    private load(projectId: number): void {
        this.loading.set(true);
        this.error.set(null);
        this.refusal.set(null);
        this.incomplete.set({});
        this.asMeasured.set(null);
        this.closeForms();
        const both = forkJoin({
            context: this.api.projectChecklistContext(projectId),
            revisions: this.api.projectChecklists(projectId)
        });
        this.readRequest.run(both, {
            next: ({ context, revisions }) => {
                this.context.set(context);
                this.revisions.set(revisions);
                this.notFound.set(false);
                if (this.writes()) this.loadOffered(projectId);
                if (context.latestRevision === null) {
                    this.view.set(null);
                    this.measurements.set(null);
                    this.loading.set(false);
                    return;
                }
                this.read(revisions[0]?.revision ?? context.latestRevision);
            },
            error: (failure) => this.failed(failure)
        });
    }

    /** One revision, the newest or an earlier one, read-only unless it is the newest draft. */
    read(revision: number): void {
        this.loading.set(true);
        this.incomplete.set({});
        this.asMeasured.set(null);
        this.closeForms();
        this.readRequest.run(this.api.projectChecklist(this.id(), revision), {
            next: (view) => {
                this.view.set(view);
                this.histories.set({});
                this.loading.set(false);
                this.measuredConflicts.set({});
                this.readMeasurements();
            },
            error: (failure) => this.failed(failure)
        });
    }

    /**
     * The measurements of the revision shown, read beside it — and only when a line is bound, so that a
     * checklist measured by no rule costs no request. A draft's and a submitted revision's are computed
     * for this read; they move with every write and every scan, so every write reads them again.
     */
    readMeasurements(): void {
        const shown = this.summary();
        this.measurementsError.set(null);
        if (!shown || !this.measured()) {
            this.measurements.set(null);
            return;
        }
        // The previous revision's, or the previous read's, must not stand for this one while it is read.
        if (this.measurements()?.revision !== shown.revision) this.measurements.set(null);
        this.measureRequest.run(this.api.checklistMeasurements(this.id(), shown.revision), {
            next: (measurements) => this.measurements.set(measurements),
            error: (failure) => {
                this.measurements.set(null);
                this.measurementsError.set(messageOf(failure, this.i18n.t('project_checklist.error_measurements')));
            }
        });
    }

    /** The line's measurement as the route answered, or null while it is read. */
    measuredOf(line: ChecklistLine): MeasuredLine | null {
        return this.measuredLines().get(line.itemId) ?? null;
    }

    /** What the last measurement refusal said of this line, or null. */
    conflictFor(line: ChecklistLine): ChecklistMeasuredConflictLine | null {
        return this.measuredConflicts()[line.itemId] ?? null;
    }

    outcomeLabel(outcome: string | null): string {
        this.i18n.translations();
        const key = outcome ? (OUTCOME_KEYS as Record<string, string | undefined>)[outcome] : undefined;
        return key ? this.i18n.t(key) : '—';
    }

    reasonShort(reason: string | null): string {
        this.i18n.translations();
        const key = reason ? (NO_DATA_SHORT_KEYS as Record<string, string | undefined>)[reason] : undefined;
        return key ? this.i18n.t(key) : '';
    }

    /** "Not met", or "No data (never examined)": what a refused line's measurement says, in words. */
    measuredWords(outcome: string | null, reason: string | null): string {
        const short = this.reasonShort(reason);
        return short ? `${this.outcomeLabel(outcome)} (${short})` : this.outcomeLabel(outcome);
    }

    private failed(failure: unknown): void {
        this.loading.set(false);
        // A project that does not exist and one not seen whole are the same 404 by design: the
        // screen cannot tell them apart and must not pretend to.
        if ((failure as { status?: number } | null)?.status === 404) {
            this.notFound.set(true);
            this.view.set(null);
            this.revisions.set([]);
            this.context.set(null);
            return;
        }
        this.error.set(messageOf(failure, this.i18n.t('project_checklist.error_load')));
    }

    private loadOffered(projectId: number): void {
        this.api.offeredChecklistVersions(projectId).subscribe({
            next: (offered) => this.offered.set(offered),
            error: () => this.offered.set([])
        });
    }

    /** The revisions listed again after a write opened one, without touching the view shown. */
    private refreshRevisions(): void {
        this.api.projectChecklists(this.id()).subscribe({
            next: (revisions) => this.revisions.set(revisions),
            error: () => undefined
        });
    }

    // ------------------------------------------------------------------ labels

    statusLabel(status: string): string {
        this.i18n.translations();
        const key = (STATUS_KEYS as Record<string, string | undefined>)[status];
        return key ? this.i18n.t(key) : status;
    }

    statusSeverity(status: string): 'warn' | 'info' | 'success' | 'secondary' {
        return status === 'draft'
            ? 'warn'
            : status === 'submitted'
              ? 'info'
              : status === 'signed_off'
                ? 'success'
                : 'secondary';
    }

    answerLabel(value: string): string {
        this.i18n.translations();
        const key = (ANSWER_KEYS as Record<string, string | undefined>)[value];
        return key ? this.i18n.t(key) : value;
    }

    /** Exposed to the template, which decides the badge, the author and the takeover hint by it. */
    readonly isAutomatic = isAutomatic;

    /**
     * Who an answer is by, as the screen names it: a system row is Vectispire's in the product's words,
     * whatever its `answeredBy` says, so that it never reads as a person's.
     */
    authorOf(answer: Pick<ChecklistAnswer, 'answeredBy' | 'answeredByKind'>): string {
        this.i18n.translations();
        return isAutomatic(answer) ? this.i18n.t('project_checklist.system_author') : answer.answeredBy;
    }

    /** The template's own word for an answer, as the importer mapped it — what the signed document will write. */
    templateWord(value: ChecklistAnswerValue): string | null {
        const words = this.view()?.answerWords;
        if (!words) return null;
        return value === 'yes' ? words.yes : value === 'no' ? words.no : words.notApplicable;
    }

    /** A carried answer onto a line that changed: the line stands out until somebody answers or confirms it. */
    awaiting(line: ChecklistLine): boolean {
        return !!line.answer?.needsConfirmation;
    }

    /** What the last refusal said keeps this line back, or `null` when it named no such thing. */
    refusedFor(line: ChecklistLine): ChecklistLineProblem[] | null {
        return this.incomplete()[line.itemId] ?? null;
    }

    problemLabel(problem: string): string {
        this.i18n.translations();
        const key = (PROBLEM_KEYS as Record<string, string | undefined>)[problem];
        return key ? this.i18n.t(key) : problem;
    }

    evidenceKindLabel(kind: string): string {
        this.i18n.translations();
        const key = (EVIDENCE_KIND_KEYS as Record<string, string | undefined>)[kind];
        return key ? this.i18n.t(key) : kind;
    }

    /** The answers the version offers: "not applicable" only where its importer mapped a word to it. */
    offeredAnswers(): readonly ChecklistAnswerValue[] {
        return this.view()?.offersNotApplicable
            ? this.answerValues
            : this.answerValues.filter((v) => v !== 'not_applicable');
    }

    private option(version: ChecklistOfferedVersion): { value: string; label: string } {
        this.i18n.translations();
        const ordinal = this.i18n.t('project_checklist.version_n', { ordinal: version.ordinal });
        return {
            value: `${version.templateSlug}:${version.ordinal}`,
            label: `${version.templateName} — ${ordinal}${version.label ? ` (${version.label})` : ''}`
        };
    }

    // ------------------------------------------------------------------ opening, moving

    /**
     * The first checklist of the project, naming the edition the context read — null, since the page
     * offers this only when the context saw no checklist, and the server refuses it when one was
     * opened since.
     */
    openChecklist(): void {
        const choice = parseChoice(this.openChoice());
        if (!choice) return;
        const edition = this.context()?.latestEdition ?? null;
        this.write(this.api.openProjectChecklist(this.id(), choice.slug, choice.ordinal, edition), null, (view) => {
            this.openChoice.set(null);
            this.notice.set(this.i18n.t('project_checklist.opened_notice', { revision: view.checklist.revision }));
            this.refreshRevisions();
        });
    }

    /** A new revision on another version, from the newest one — the edition read on it. */
    moveChecklist(): void {
        const choice = parseChoice(this.moveChoice());
        const shown = this.summary();
        if (!choice || !shown) return;
        this.write(
            this.api.openProjectChecklist(this.id(), choice.slug, choice.ordinal, shown.edition),
            null,
            (view) => {
                this.moveChoice.set(null);
                this.notice.set(
                    this.i18n.t('project_checklist.moved_notice', {
                        revision: view.checklist.revision,
                        ordinal: view.checklist.versionOrdinal
                    })
                );
                this.refreshRevisions();
            }
        );
    }

    reopen(): void {
        const shown = this.summary();
        if (!shown) return;
        this.write(this.api.reopenChecklist(this.id(), shown.revision, shown.edition), null, (view) => {
            this.notice.set(this.i18n.t('project_checklist.reopened_notice', { revision: view.checklist.revision }));
            this.refreshRevisions();
        });
    }

    // ------------------------------------------------------------------ answering

    startAnswer(line: ChecklistLine): void {
        this.proving.set(null);
        this.answerError.set(null);
        this.answering.set({
            itemId: line.itemId,
            value: line.answer?.value ?? null,
            comment: line.answer?.comment ?? '',
            restingOn: null
        });
    }

    /**
     * The one click a measured line offers (§6): the person's answer, resting on the measurement they
     * read, named by its evidence digest. Met, it is a yes and is sent at once; not met, it is a no, and
     * a no needs its comment — the form opens with the answer chosen and the measurement kept with it.
     */
    answerAsMeasured(line: ChecklistLine): void {
        const measured = this.measuredOf(line);
        const shown = this.summary();
        const value = measuredAnswer(measured);
        const found = measured?.measurement;
        if (!shown || !value || !found) return;
        const restingOn = { digest: found.evidenceDigest, value, computedAt: found.computedAt };
        if (value === 'no') {
            this.proving.set(null);
            this.answerError.set(null);
            this.answering.set({ itemId: line.itemId, value, comment: line.answer?.comment ?? '', restingOn });
            return;
        }
        this.answering.set(null);
        this.write(
            this.api.answerChecklistLine(
                this.id(),
                shown.revision,
                line.itemId,
                value,
                null,
                shown.edition,
                restingOn.digest
            ),
            line.itemId
        );
    }

    /**
     * The one click for every line that offers it, in one act: the met ones are answered yes, each
     * resting on the measurement its button showed; the rest are named in the summary with why. The
     * lines sent are exactly `asMeasuredOffer`'s — never a line the person was not shown.
     */
    answerAllAsMeasured(): void {
        const shown = this.summary();
        const lines = this.asMeasuredOffer();
        if (!shown || lines.length === 0) return;
        this.answering.set(null);
        this.asMeasured.set(null);
        this.send(
            this.api.answerChecklistAsMeasured(this.id(), shown.revision, lines, shown.edition),
            (result) => result.checklist,
            null,
            (result: ChecklistAsMeasured) =>
                this.asMeasured.set({
                    revision: result.checklist.checklist.revision,
                    answered: result.answered.length,
                    sent: new Set(lines.map((line) => line.itemId)),
                    skipped: result.skipped
                })
        );
    }

    /**
     * A line the act left for the person's no: its form opens on no, resting on the measurement, and
     * the comment it needs takes the focus. Should the measurement no longer say not met — read again
     * after the act — the plain form opens instead, and the person reads the line before answering.
     */
    answerNoFromSummary(itemId: number): void {
        const line = this.view()?.lines.find((one) => one.itemId === itemId);
        if (!line) return;
        if (measuredAnswer(this.measuredOf(line)) === 'no') this.answerAsMeasured(line);
        else this.startAnswer(line);
        afterNextRender(() => document.getElementById(`comment-${itemId}`)?.focus(), { injector: this.injector });
    }

    asMeasuredLabel(group: AsMeasuredGroup): string {
        this.i18n.translations();
        return this.i18n.t(AS_MEASURED_SKIP_KEYS[group.reason], {
            lines: group.lines.map((line) => line.position).join(', ')
        });
    }

    setAnswer(patch: Partial<Pick<AnswerDraft, 'value' | 'comment'>>): void {
        this.answering.update((draft) => (draft ? { ...draft, ...patch } : draft));
    }

    /** Refused here as the server would: no answer chosen, or a negative one without its reason. */
    saveAnswer(line: ChecklistLine): void {
        const draft = this.answering();
        const shown = this.summary();
        if (!draft || !shown || draft.itemId !== line.itemId) return;
        if (!draft.value) {
            this.answerError.set(this.i18n.t('project_checklist.problem_choose'));
            return;
        }
        if (draft.value !== 'yes' && !draft.comment.trim()) {
            this.answerError.set(this.i18n.t('project_checklist.problem_comment'));
            return;
        }
        this.answerError.set(null);
        this.write(
            this.api.answerChecklistLine(
                this.id(),
                shown.revision,
                line.itemId,
                draft.value,
                draft.comment,
                shown.edition,
                draft.restingOn?.value === draft.value ? draft.restingOn.digest : null
            ),
            line.itemId,
            () => this.answering.set(null)
        );
    }

    confirmAnswer(line: ChecklistLine): void {
        const shown = this.summary();
        if (!shown) return;
        this.write(this.api.confirmChecklistAnswer(this.id(), shown.revision, line.itemId, shown.edition), line.itemId);
    }

    // ------------------------------------------------------------------ evidence

    startEvidence(line: ChecklistLine): void {
        this.answering.set(null);
        this.evidenceError.set(null);
        this.proving.set({
            itemId: line.itemId,
            kind: line.evidenceKind === 'file' ? 'file' : 'link',
            link: '',
            file: null,
            performedOn: this.today
        });
    }

    setEvidence(patch: Partial<Pick<EvidenceDraft, 'kind' | 'link' | 'performedOn'>>): void {
        this.proving.update((draft) => (draft ? { ...draft, ...patch } : draft));
    }

    /**
     * Refused past the route's ceiling before anything is sent, in the sentence the server's body
     * filter answers with — twenty-five megabytes uploaded to be told no is the refusal that costs.
     */
    pickEvidence(event: Event): void {
        const input = event.target as HTMLInputElement;
        const file = input.files?.[0] ?? null;
        this.evidenceError.set(null);
        if (file && file.size > MAX_EVIDENCE_BYTES) {
            input.value = '';
            this.proving.update((draft) => (draft ? { ...draft, file: null } : draft));
            this.evidenceError.set(this.i18n.t('project_checklist.too_large', { limit: MAX_EVIDENCE_BYTES }));
            return;
        }
        this.proving.update((draft) => (draft ? { ...draft, file } : draft));
    }

    saveEvidence(line: ChecklistLine): void {
        const draft = this.proving();
        const shown = this.summary();
        if (!draft || !shown || draft.itemId !== line.itemId) return;
        if (!DAY.test(draft.performedOn) || draft.performedOn > this.today) {
            this.evidenceError.set(this.i18n.t('project_checklist.problem_day'));
            return;
        }
        let request: Observable<ChecklistView>;
        if (draft.kind === 'link') {
            if (!LINK.test(draft.link.trim())) {
                this.evidenceError.set(this.i18n.t('project_checklist.problem_link'));
                return;
            }
            request = this.api.attachChecklistLink(
                this.id(),
                shown.revision,
                line.itemId,
                draft.link,
                draft.performedOn,
                shown.edition
            );
        } else {
            if (!draft.file) {
                this.evidenceError.set(this.i18n.t('project_checklist.problem_file'));
                return;
            }
            request = this.api.attachChecklistFile(
                this.id(),
                shown.revision,
                line.itemId,
                draft.file,
                draft.performedOn,
                shown.edition
            );
        }
        this.evidenceError.set(null);
        this.write(request, line.itemId, () => this.proving.set(null));
    }

    withdraw(proof: ChecklistEvidence): void {
        const shown = this.summary();
        if (!shown) return;
        this.write(
            this.api.withdrawChecklistEvidence(this.id(), shown.revision, proof.id, shown.edition),
            proof.itemId
        );
    }

    /**
     * Saved as a download under the name the list shows, never opened in the page. The name is the
     * one the proof was stored under, rather than the header's, which `filenameOf` reads only in its
     * plain form and a name outside ASCII does not take.
     */
    download(proof: ChecklistEvidence): void {
        const shown = this.summary();
        if (!shown) return;
        this.api.checklistEvidenceFile(this.id(), shown.revision, proof.id).subscribe({
            next: (response) =>
                saveDocument(response.clone({ headers: new HttpHeaders() }), proof.fileName ?? 'evidence'),
            error: (failure) => this.error.set(messageOf(failure, this.i18n.t('project_checklist.error_download')))
        });
    }

    // ------------------------------------------------------------------ the document

    /**
     * Whether the revision's document is called signed. **Only its status can say so**: a signed-off
     * revision's package was signed at its sign-off — except one signed off before documents were, which
     * the server renders unsigned and the screen cannot tell apart. So the screen says "signed package"
     * for a signed-off revision and nothing stronger, and the guide names the exception.
     */
    documentSigned(status: string): boolean {
        return status === 'signed_off';
    }

    /** The name the server gives the zip, which the verification commands unpack. */
    documentName(revision: number): string {
        return `checklist-project-${this.id()}-revision-${revision}.zip`;
    }

    /**
     * Saved as a download, never opened. A 404 is a project this account no longer sees whole, or a
     * revision gone — the words of an absence, as everywhere on this page: the checklist is read again.
     * The body of a blob request's refusal is a Blob, so its problem type is not read here; the status
     * is all a 404 needs.
     */
    downloadDocument(revision: number): void {
        this.downloading.set(revision);
        this.api.checklistDocument(this.id(), revision).subscribe({
            next: (response) => {
                this.downloading.set(null);
                saveDocument(response, this.documentName(revision));
            },
            error: (failure) => {
                this.downloading.set(null);
                if ((failure as { status?: number } | null)?.status === 404) {
                    this.refusal.set({
                        message: this.i18n.t('project_checklist.document_not_found', { revision }),
                        reload: true,
                        itemId: null
                    });
                    return;
                }
                this.error.set(messageOf(failure, this.i18n.t('project_checklist.error_document')));
            }
        });
    }

    /**
     * The guide's commands for the revision shown, when it is signed off: unpack, then check each entry
     * against the key fetched on its own — `--insecure-ignore-tlog=true` because Vectispire publishes no
     * transparency-log entry, and cosign fails looking for one without it.
     */
    readonly verificationCommands = computed(() => {
        const shown = this.summary();
        if (!shown || !this.documentSigned(shown.status)) return null;
        return [
            `curl -fsS -o ${PUBLIC_KEY_FILE} "${window.location.origin}${PUBLIC_KEY_PATH}"`,
            `unzip ${this.documentName(shown.revision)}`,
            ...['checklist.xlsx', 'checklist.json'].map(
                (entry) =>
                    `cosign verify-blob --key ${PUBLIC_KEY_FILE} --insecure-ignore-tlog=true --signature ${entry}.sig ${entry}`
            )
        ].join('\n');
    });

    copyCommands(commands: string): void {
        void navigator.clipboard.writeText(commands).then(() => {
            this.copied.set(true);
            setTimeout(() => this.copied.set(false), 3000);
        });
    }

    // ------------------------------------------------------------------ history

    historyOpen(line: ChecklistLine): boolean {
        return line.itemId in this.histories();
    }

    toggleHistory(line: ChecklistLine): void {
        const shown = this.summary();
        if (!shown) return;
        if (this.historyOpen(line)) {
            this.histories.update((open) => {
                const rest = { ...open };
                delete rest[line.itemId];
                return rest;
            });
            return;
        }
        this.histories.update((open) => ({ ...open, [line.itemId]: null }));
        this.api.checklistLineHistory(this.id(), shown.revision, line.itemId).subscribe({
            next: (history) => this.histories.update((open) => ({ ...open, [line.itemId]: history })),
            error: (failure) => {
                this.histories.update((open) => {
                    const rest = { ...open };
                    delete rest[line.itemId];
                    return rest;
                });
                this.error.set(messageOf(failure, this.i18n.t('project_checklist.error_history')));
            }
        });
    }

    // ------------------------------------------------------------------ submitting, returning, signing off

    submit(): void {
        const shown = this.summary();
        if (!shown) return;
        this.write(this.api.submitChecklist(this.id(), shown.revision, shown.edition), null, (view) =>
            this.notice.set(this.i18n.t('project_checklist.submitted_notice', { revision: view.checklist.revision }))
        );
    }

    startReturn(): void {
        this.returning.set(true);
        this.returnReason.set('');
        this.returnError.set(null);
    }

    confirmReturn(): void {
        const shown = this.summary();
        if (!shown) return;
        if (!this.returnReason().trim()) {
            this.returnError.set(this.i18n.t('project_checklist.problem_reason'));
            return;
        }
        this.returnError.set(null);
        this.write(
            this.api.returnChecklist(this.id(), shown.revision, this.returnReason(), shown.edition),
            null,
            (view) => {
                this.returning.set(false);
                this.notice.set(
                    this.i18n.t('project_checklist.returned_notice', { revision: view.checklist.revision })
                );
            }
        );
    }

    signOff(): void {
        const shown = this.summary();
        if (!shown) return;
        this.write(this.api.signOffChecklist(this.id(), shown.revision, shown.edition), null, (view) =>
            this.notice.set(this.i18n.t('project_checklist.signed_notice', { revision: view.checklist.revision }))
        );
    }

    // ------------------------------------------------------------------ writing

    /**
     * One write: the view it answers replaces the one shown — its edition is the one the next write
     * names — and the revision's row in the list follows. A refusal is explained, never swallowed.
     */
    private write(
        request: Observable<ChecklistView>,
        itemId: number | null,
        done?: (view: ChecklistView) => void
    ): void {
        this.send(request, (view) => view, itemId, done);
    }

    /** A write whose answer carries the view beside something else — the as-measured act's summary. */
    private send<T>(
        request: Observable<T>,
        viewOf: (result: T) => ChecklistView,
        itemId: number | null,
        done?: (result: T) => void
    ): void {
        this.busy.set(true);
        this.refusal.set(null);
        this.incomplete.set({});
        this.measuredConflicts.set({});
        this.error.set(null);
        this.notice.set(null);
        request.subscribe({
            next: (result) => {
                this.busy.set(false);
                this.adopt(viewOf(result));
                done?.(result);
            },
            error: (failure) => {
                this.busy.set(false);
                this.refusal.set(this.explain(failure, itemId));
            }
        });
    }

    private adopt(view: ChecklistView): void {
        this.view.set(view);
        this.histories.set({});
        const summary = view.checklist;
        this.revisions.update((revisions) =>
            revisions.some((one) => one.revision === summary.revision)
                ? revisions.map((one) => (one.revision === summary.revision ? summary : one))
                : [summary, ...revisions]
        );
        // The newest revision's edition moved with the write: the context says so too.
        this.context.update((context) =>
            context && (context.latestRevision === null || summary.revision >= context.latestRevision)
                ? { ...context, latestRevision: summary.revision, latestEdition: summary.edition }
                : context
        );
        // An answer moves its line's reconciliation, a submission or a sign-off what is live or frozen.
        this.readMeasurements();
    }

    /** A cause named by the problem's type gets its sentence; anything else, the server's own words. */
    private explain(failure: unknown, itemId: number | null): Refusal {
        const cause = conflictOf(failure);
        if (!cause) {
            return {
                message: messageOf(failure, this.i18n.t('project_checklist.error_write')),
                reload: false,
                itemId
            };
        }
        if (cause === 'measurement_contradicted' || cause === 'measurement_changed') {
            return this.explainMeasured(cause, failure, itemId);
        }
        if (cause === 'version_unrenderable') {
            return this.explainUnrenderable(failure, itemId);
        }
        // The lines the refusal names, as data, over the ones the view shows: the server's are the
        // ones it refused for, and a proof that lapsed since the view was read is on no line here.
        const named = cause === 'incomplete' ? incompleteLinesOf(failure) : null;
        if (named) {
            this.incomplete.set(Object.fromEntries(named.map((line) => [line.itemId, line.problems])));
        }
        const lines = named ? named.map((line) => line.position).sort((a, b) => a - b) : this.unready();
        const message =
            cause === 'incomplete' && lines.length === 0
                ? this.i18n.t('project_checklist.conflict_incomplete_reload')
                : this.i18n.t(CONFLICT_KEYS[cause], {
                      lines: lines.join(', '),
                      authors: (this.view()?.authors ?? []).join(', ')
                  });
        // Four-eyes is the one cause reloading does not cure: the person is who they are.
        return { message, reload: cause !== 'four_eyes', itemId };
    }

    /**
     * A measurement refused the write: the lines it names are highlighted with what the rule finds now
     * — and, at a sign-off, what it found at the submission — and the measurements are read again, since
     * the ones on screen are, by the refusal's own account, not the server's any more.
     *
     * On an answer (a line named), `checklist-measurement-changed` means the evidence moved between the
     * read and the click: the person reads the new measurement before answering again.
     */
    private explainMeasured(
        cause: 'measurement_contradicted' | 'measurement_changed',
        failure: unknown,
        itemId: number | null
    ): Refusal {
        const named = measuredConflictLinesOf(failure) ?? [];
        this.measuredConflicts.set(Object.fromEntries(named.map((line) => [line.itemId, line])));
        this.readMeasurements();
        if (cause === 'measurement_changed' && itemId !== null) {
            return {
                message: this.i18n.t('project_checklist.conflict_measurement_changed_answer'),
                reload: false,
                itemId
            };
        }
        const lines = named.map((line) => line.position).sort((a, b) => a - b);
        return {
            message: this.i18n.t(CONFLICT_KEYS[cause], { lines: lines.join(', ') || '—' }),
            reload: true,
            itemId
        };
    }

    /**
     * The version chosen is one no sign-off could fill in — published before its publication tried — so
     * nothing was opened or moved. The cells are named for whoever corrects the workbook; reloading cures
     * nothing, since a published version's workbook never changes: a corrected version is the way.
     */
    private explainUnrenderable(failure: unknown, itemId: number | null): Refusal {
        const cells = unrenderableCellsOf(failure);
        return {
            // Refused for another reason than a formula: the server's words, rather than a sentence naming no cell.
            message: cells
                ? this.i18n.t(CONFLICT_KEYS.version_unrenderable, {
                      cells: describeUnrenderableCells(this.i18n, cells)
                  })
                : messageOf(failure, this.i18n.t('project_checklist.error_write')),
            reload: false,
            itemId
        };
    }

    private closeForms(): void {
        this.answering.set(null);
        this.proving.set(null);
        this.returning.set(false);
        this.answerError.set(null);
        this.evidenceError.set(null);
    }
}

// ---------------------------------------------------------------------- pure helpers

const DAY = /^\d{4}-\d{2}-\d{2}$/;
/** What the server accepts as a link proof: `https:` or `http:` with a host. It checks again. */
const LINK = /^https?:\/\/[^\s/?#]+/i;

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

function parseChoice(choice: string | null): { slug: string; ordinal: number } | null {
    if (!choice) return null;
    const at = choice.lastIndexOf(':');
    const ordinal = Number(choice.slice(at + 1));
    return at > 0 && Number.isInteger(ordinal) ? { slug: choice.slice(0, at), ordinal } : null;
}

/** Today as the server reads a proof's day — in UTC, so that a day it calls future is not offered. */
function todayUtc(): string {
    return new Date().toISOString().slice(0, 10);
}
