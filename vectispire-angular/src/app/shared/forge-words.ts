import type { ForgeDiscoveryReason, ForgeDiscoveryState, ForgeSkipReason } from '../core/api.models';

/**
 * The words of decision 0037's closed vocabularies, as literal keys (decision 0019): a value added on the
 * server fails to compile here — or, for a field the document types `string`, is shown as sent — rather than
 * reaching the reader as a key path.
 */
export const DISCOVERY_STATE_KEYS = {
    pending: 'forges.discovery.state.pending',
    running: 'forges.discovery.state.running',
    completed: 'forges.discovery.state.completed',
    partial: 'forges.discovery.state.partial',
    failed: 'forges.discovery.state.failed'
} as const satisfies Record<ForgeDiscoveryState, string>;

/** Partial and failed alike: what happened, and what the administrator does about it. */
export const DISCOVERY_REASON_KEYS = {
    time_bound: 'forges.discovery.reason.time_bound',
    repository_bound: 'forges.discovery.reason.repository_bound',
    rate_limited: 'forges.discovery.reason.rate_limited',
    token_rejected: 'forges.discovery.reason.token_rejected',
    destination_blocked: 'forges.discovery.reason.destination_blocked',
    cross_origin_page: 'forges.discovery.reason.cross_origin_page',
    forge_unavailable: 'forges.discovery.reason.forge_unavailable',
    forge_refused: 'forges.discovery.reason.forge_refused',
    connection_unusable: 'forges.discovery.reason.connection_unusable',
    unsupported: 'forges.discovery.reason.unsupported',
    executor_lost: 'forges.discovery.reason.executor_lost',
    internal_error: 'forges.discovery.reason.internal_error'
} as const satisfies Record<ForgeDiscoveryReason, string>;

/** Why a repository cannot be ticked, or was skipped by an import. */
export const SKIP_REASON_KEYS = {
    already_imported: 'forges.skip.already_imported',
    already_present: 'forges.skip.already_present',
    no_default_branch: 'forges.skip.no_default_branch',
    no_clone_url: 'forges.skip.no_clone_url',
    duplicate_in_selection: 'forges.skip.duplicate_in_selection'
} as const satisfies Record<ForgeSkipReason, string>;

/** `ForgeEdition.wireName()` — the document types it `string`. */
export const EDITION_KEYS: Readonly<Record<string, string>> = {
    github_com: 'forges.edition.github_com',
    github_data_residency: 'forges.edition.github_data_residency',
    github_enterprise_server: 'forges.edition.github_enterprise_server',
    gitlab_com: 'forges.edition.gitlab_com',
    gitlab_self_managed: 'forges.edition.gitlab_self_managed'
};

/** `ForgeCredential.Kind.wireName()` — the kind of token the forge's answers identified. */
export const CREDENTIAL_KIND_KEYS: Readonly<Record<string, string>> = {
    github_fine_grained: 'forges.credential.github_fine_grained',
    github_classic: 'forges.credential.github_classic',
    gitlab_bot: 'forges.credential.gitlab_bot',
    gitlab_personal: 'forges.credential.gitlab_personal'
};

/** The clone credential an import uses per host: `ssh_key`, `https_token` or `none`. */
export const CLONE_CREDENTIAL_KEYS: Readonly<Record<string, string>> = {
    ssh_key: 'forges.import.credential_ssh_key',
    https_token: 'forges.import.credential_https_token',
    none: 'forges.import.credential_none'
};

/** The filters that may meet a value the forge did not give — `SelectionFilter.Judged`. */
export const UNJUDGED_KEYS: Readonly<Record<string, string>> = {
    archived: 'forges.selection.unjudged_archived',
    fork: 'forges.selection.unjudged_fork',
    activity: 'forges.selection.unjudged_activity',
    language: 'forges.selection.unjudged_language',
    visibility: 'forges.selection.unjudged_visibility'
};

/** What the screen can tell of a pasted CA before sending it; the server judges the rest. */
export type CaProblem = 'private_key' | 'not_pem' | 'unbalanced' | 'too_many';

export const CA_PROBLEM_KEYS = {
    private_key: 'forges.ca.private_key',
    not_pem: 'forges.ca.not_pem',
    unbalanced: 'forges.ca.unbalanced',
    too_many: 'forges.ca.too_many'
} as const satisfies Record<CaProblem, string>;

/** `PinnedCa`'s bound: a bundle of more is refused by the server, and said here before the round trip. */
export const MAX_CA_CERTIFICATES = 8;

/**
 * The first thing wrong with a pasted CA that can be seen without parsing it, or `null`.
 *
 * Only the shape: whether a block is a CA, and whether it is still valid, is the server's to say (in words,
 * through `detail`) — a second parser here would be a second rule to keep agreeing with `PinnedCa`. A
 * private key is caught first because pasting one is the mistake that matters: it would be sent to the
 * server, which has no use for it.
 */
export function caPemProblem(pem: string): CaProblem | null {
    const text = pem.trim();
    if (!text) return null;
    if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(text)) return 'private_key';
    const begins = (text.match(/-----BEGIN CERTIFICATE-----/g) ?? []).length;
    const ends = (text.match(/-----END CERTIFICATE-----/g) ?? []).length;
    if (begins === 0 && ends === 0) return 'not_pem';
    if (begins !== ends) return 'unbalanced';
    if (begins > MAX_CA_CERTIFICATES) return 'too_many';
    return null;
}

/** How many certificates a pasted bundle holds, once its shape is right. */
export function caCertificateCount(pem: string): number {
    return (pem.match(/-----BEGIN CERTIFICATE-----/g) ?? []).length;
}

/**
 * Whether an address names a vendor's cloud — blank, github.com, gitlab.com or a ghe.com subdomain — for
 * which the server refuses both the internal-network statement and a pinned CA (`ForgeAddress`). The form
 * greys the two out rather than letting the server refuse what it already knows to refuse.
 */
export function isCloudAddress(baseUrl: string): boolean {
    const typed = baseUrl.trim();
    if (!typed) return true;
    let host: string;
    try {
        host = new URL(typed).hostname.toLowerCase();
    } catch {
        return false;
    }
    return (
        ['github.com', 'www.github.com', 'api.github.com', 'gitlab.com', 'www.gitlab.com'].includes(host) ||
        host.endsWith('.ghe.com')
    );
}

/** The fourteen days before a reported expiry during which the list announces it (decision 0037 §2). */
export const EXPIRY_NOTICE_DAYS = 14;

export type ExpiryState = 'none' | 'valid' | 'soon' | 'expired';

/** Where a token's reported expiry stands at `now`. `none`: the forge reported no expiry. */
export function expiryState(expiresAt: string | null | undefined, now: Date): ExpiryState {
    if (!expiresAt) return 'none';
    const at = new Date(expiresAt).getTime();
    if (Number.isNaN(at)) return 'none';
    if (at <= now.getTime()) return 'expired';
    return at - now.getTime() <= EXPIRY_NOTICE_DAYS * 86_400_000 ? 'soon' : 'valid';
}

/** Whole days left before an expiry, at least one while it has not passed. */
export function daysLeft(expiresAt: string, now: Date): number {
    return Math.max(1, Math.ceil((new Date(expiresAt).getTime() - now.getTime()) / 86_400_000));
}

/** The causes a forge route's 409 names (`ForgeDiscoveryConflict.Cause`), told apart by the problem's type. */
export type ForgeConflictCause =
    | 'forge-discovery-in-progress'
    | 'forge-discovery-unsupported'
    | 'forge-discovery-not-selectable'
    | 'forge-discovery-superseded';

export interface ForgeConflict {
    cause: ForgeConflictCause;
    /** The running discovery, for `forge-discovery-in-progress`. */
    discoveryId: number | null;
    /** The discovery to select from instead, for `forge-discovery-superseded`. */
    latestDiscoveryId: number | null;
    /** The state of a discovery that is not selectable. */
    state: string | null;
}

const CONFLICT_CAUSES: readonly ForgeConflictCause[] = [
    'forge-discovery-in-progress',
    'forge-discovery-unsupported',
    'forge-discovery-not-selectable',
    'forge-discovery-superseded'
];

/**
 * The conflict a refused request names, read from the problem's `type` and its members rather than from
 * its sentence — which is English and changes with its wording — or `null` for anything else.
 */
export function forgeConflict(response: unknown): ForgeConflict | null {
    const failure = response as { status?: number; error?: unknown } | null;
    if (failure?.status !== 409 || !failure.error || typeof failure.error !== 'object') return null;
    const problem = failure.error as Record<string, unknown>;
    const type = typeof problem['type'] === 'string' ? problem['type'] : '';
    const cause = CONFLICT_CAUSES.find((known) => type === `urn:vectispire:problem:${known}`);
    if (!cause) return null;
    const number = (value: unknown) => (typeof value === 'number' ? value : null);
    return {
        cause,
        discoveryId: number(problem['discoveryId']),
        latestDiscoveryId: number(problem['latestDiscoveryId']),
        state: typeof problem['state'] === 'string' ? problem['state'] : null
    };
}
