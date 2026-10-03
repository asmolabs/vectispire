import type { ReportManifestStatus, ReportMediaType, ReportRunReason, ReportRunState } from '../core/api.models';

/**
 * The words of report plugins (decision 0035), one list each, shared by the registry and the project
 * page. Literal keys over the generated unions (decision 0019): a state or a reason the server adds
 * fails to compile here, rather than reaching a reader as a raw word.
 */

export const RUN_STATE_KEYS = {
    pending: 'reports.state.pending',
    running: 'reports.state.running',
    produced: 'reports.state.produced',
    failed: 'reports.state.failed',
    refused: 'reports.state.refused'
} as const satisfies Record<ReportRunState, string>;

/**
 * **A refusal is not a failure, and the two must not look alike.** `failed` is work going wrong — an
 * exit code, a timeout; `refused` is an image nobody vouched for, or a file that is not what it
 * declared, which is how a tampered plugin shows itself (VECTI-SEC-033).
 */
export const RUN_STATE_SEVERITY = {
    pending: 'secondary',
    running: 'info',
    produced: 'success',
    failed: 'warn',
    refused: 'danger'
} as const satisfies Record<ReportRunState, 'secondary' | 'info' | 'success' | 'warn' | 'danger'>;

/** The runs the page waits on: anything else has ended and will not change. */
export const ACTIVE_RUN_STATES: readonly ReportRunState[] = ['pending', 'running'];

export const RUN_REASON_KEYS = {
    unsigned: 'reports.reason.unsigned',
    signature_unverified: 'reports.reason.signature_unverified',
    registry_authentication_required: 'reports.reason.registry_authentication_required',
    export_schema_unavailable: 'reports.reason.export_schema_unavailable',
    output_refused: 'reports.reason.output_refused',
    exit_code: 'reports.reason.exit_code',
    timeout: 'reports.reason.timeout',
    output_full: 'reports.reason.output_full',
    output_missing: 'reports.reason.output_missing',
    output_not_regular: 'reports.reason.output_not_regular',
    export_too_large: 'reports.reason.export_too_large',
    requester_not_allowed: 'reports.reason.requester_not_allowed',
    plugin_unavailable: 'reports.reason.plugin_unavailable',
    executor_lost: 'reports.reason.executor_lost',
    executor_unavailable: 'reports.reason.executor_unavailable',
    executor_error: 'reports.reason.executor_error'
} as const satisfies Record<ReportRunReason, string>;

export const MANIFEST_STATUS_KEYS = {
    pending_approval: 'report_plugins.status.pending_approval',
    approved: 'report_plugins.status.approved',
    superseded: 'report_plugins.status.superseded',
    withdrawn: 'report_plugins.status.withdrawn'
} as const satisfies Record<ReportManifestStatus, string>;

export const MANIFEST_STATUS_SEVERITY = {
    pending_approval: 'warn',
    approved: 'success',
    superseded: 'secondary',
    withdrawn: 'danger'
} as const satisfies Record<ReportManifestStatus, 'warn' | 'success' | 'secondary' | 'danger'>;

/** The extension a reader recognises a type by; the names are the formats' own, not translated. */
export const MEDIA_TYPE_EXTENSIONS = {
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': '.xlsx',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '.docx',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation': '.pptx',
    'application/vnd.oasis.opendocument.spreadsheet': '.ods',
    'application/vnd.oasis.opendocument.text': '.odt',
    'application/pdf': '.pdf',
    'text/csv': '.csv',
    'text/plain': '.txt'
} as const satisfies Record<ReportMediaType, string>;

export const MEDIA_TYPES = Object.keys(MEDIA_TYPE_EXTENSIONS) as ReportMediaType[];

/**
 * A report plugin's 409, by cause: `ReportPluginConflict.Cause`, read from the problem's `type` — never
 * from its English `detail`, so the reader gets the sentence in their language.
 */
export type ReportConflict =
    | 'id_taken'
    | 'not_pending'
    | 'four_eyes'
    | 'not_approved'
    | 'withdrawn'
    | 'changed'
    | 'disabled'
    | 'executor_unavailable'
    | 'run_in_progress';

const CONFLICT_TYPES: Readonly<Record<string, ReportConflict>> = {
    'urn:vectispire:problem:report-plugin-id-taken': 'id_taken',
    'urn:vectispire:problem:report-plugin-not-pending': 'not_pending',
    'urn:vectispire:problem:report-plugin-four-eyes': 'four_eyes',
    'urn:vectispire:problem:report-plugin-not-approved': 'not_approved',
    'urn:vectispire:problem:report-plugin-withdrawn': 'withdrawn',
    'urn:vectispire:problem:report-plugin-changed': 'changed',
    'urn:vectispire:problem:report-plugin-disabled': 'disabled',
    'urn:vectispire:problem:report-executor-unavailable': 'executor_unavailable',
    'urn:vectispire:problem:report-run-in-progress': 'run_in_progress'
};

export const CONFLICT_KEYS = {
    id_taken: 'reports.conflict.id_taken',
    not_pending: 'reports.conflict.not_pending',
    four_eyes: 'reports.conflict.four_eyes',
    not_approved: 'reports.conflict.not_approved',
    withdrawn: 'reports.conflict.withdrawn',
    changed: 'reports.conflict.changed',
    disabled: 'reports.conflict.disabled',
    executor_unavailable: 'reports.conflict.executor_unavailable',
    run_in_progress: 'reports.conflict.run_in_progress'
} as const satisfies Record<ReportConflict, string>;

/** The cause of a 409 this module names, or null for any other failure. */
export function reportConflictOf(failure: unknown): ReportConflict | null {
    const response = failure as { status?: number; error?: { type?: unknown } } | null;
    if (response?.status !== 409) return null;
    const type = response.error?.type;
    return typeof type === 'string' && Object.hasOwn(CONFLICT_TYPES, type) ? CONFLICT_TYPES[type] : null;
}

export function isNotFound(failure: unknown): boolean {
    return (failure as { status?: number } | null)?.status === 404;
}

/** The first twelve hex digits, the way digests are shown everywhere else. */
export function shortDigest(digest: string | null | undefined): string {
    return digest ? digest.replace(/^sha256:/, '').slice(0, 12) : '—';
}
