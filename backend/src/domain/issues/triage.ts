/**
 * The rules of a triage decision — validation and expiry.
 *
 * In the domain, hence with no database: these are vocabulary rules and date arithmetic,
 * and they can be tested exhaustively. The service then applies the result to a row.
 *
 * The vocabulary is declared **here** rather than taken from the entities: the layering
 * rule forbids the domain from knowing about persistence, and that is the right direction
 * for the dependency — the VEX vocabulary exists independently of the table storing it.
 */

export const TRIAGE_UNDER_REVIEW = 'under_review';
export const TRIAGE_AFFECTED = 'affected';
export const TRIAGE_NOT_AFFECTED = 'not_affected';
export const TRIAGE_FIXED = 'fixed';

export class InvalidTriageError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'InvalidTriageError';
    }
}

export interface TriageRequest {
    status: string;
    actor: string;
    justification?: string | null;
    comment?: string | null;
    /**
     * A review date, **offered and not imposed**: deciding that a component is simply not
     * present needs no scheduled re-examination, whereas "not reachable in our
     * configuration" badly does — and only the person deciding knows which of the two
     * they have just recorded.
     */
    expiresInDays?: number | null;
}

export interface TriageDecision {
    status: string;
    justification: string | null;
    comment: string | null;
    triagedBy: string;
    triagedAt: Date;
    expiresAt: Date | null;
}

/**
 * Validates a triage request and computes what has to be written.
 *
 * Throws `InvalidTriageError` on anything invalid, with a message meant to be shown as
 * is: it is the person doing the triage who needs to know why their decision is refused.
 *
 * @param asOf The instant of the decision.
 */
export function decideTriage(request: TriageRequest, asOf: Date): TriageDecision {
    if (!VALID_TRIAGE_STATUSES.includes(request.status)) {
        throw new InvalidTriageError(`Invalid triage status: ${request.status}`);
    }

    const justification = (request.justification ?? '').trim() || null;
    if (justification && !VEX_JUSTIFICATIONS.includes(justification)) {
        throw new InvalidTriageError(`Unknown VEX justification: ${justification}`);
    }
    // VEX **requires** a justification for "not_affected": without one the statement
    // carries no information, and an exported VEX document containing it would be
    // invalid.
    if (request.status === TRIAGE_NOT_AFFECTED && !justification) {
        throw new InvalidTriageError('A justification is required for the "not affected" status (VEX requirement).');
    }

    return {
        status: request.status,
        justification,
        comment: (request.comment ?? '').trim() || null,
        triagedBy: request.actor,
        triagedAt: asOf,
        expiresAt: expiryFrom(request.status, request.expiresInDays ?? null, asOf)
    };
}

/**
 * A review date, or `null`.
 *
 * Returning to `under_review` clears any expiry: the issue is already in the queue, and a
 * date to bring it back there would fire on nothing.
 */
export function expiryFrom(status: string, expiresInDays: number | null, asOf: Date): Date | null {
    if (status === TRIAGE_UNDER_REVIEW || expiresInDays === null || expiresInDays === undefined) return null;

    // `null` means "no review date"; zero or a negative number means the caller got
    // their arithmetic wrong, and silently treating it as "never" would hide the
    // mistake.
    const days = Math.trunc(expiresInDays);
    if (days <= 0) throw new InvalidTriageError('The review delay must be at least one day.');

    return addDays(asOf, days);
}

/**
 * Is a decision past its review date?
 *
 * A suppression is a statement about a context, and contexts change. Without this expiry,
 * a `not_affected` placed in January stayed authoritative in December — in the VEX
 * document handed to a customer as much as on the dashboard. That is how VEX suppressions
 * rot.
 */
export function isTriageExpired(issue: { triageStatus: string | null; triageExpiresAt: Date | null }, asOf: Date): boolean {
    if (!issue.triageExpiresAt || issue.triageStatus === TRIAGE_UNDER_REVIEW) return false;
    return asOf >= issue.triageExpiresAt;
}

/**
 * What an expiry changes on an issue — and above all what it does **not**.
 *
 * The justification and the comment are *kept*. The decision had a reason, and whoever
 * re-examines it needs to see it: erasing the text would turn a scheduled review into an
 * investigation started from scratch, which is how a review date becomes something people
 * stop filling in.
 *
 * `triagedBy` and `triagedAt` are kept for the same reason, and because they are the
 * record of who said what: overwriting them would erase evidence.
 */
export function expireTriage<T extends { triageStatus: string | null; triageExpiresAt: Date | null }>(issue: T): T {
    issue.triageStatus = TRIAGE_UNDER_REVIEW;
    issue.triageExpiresAt = null;
    return issue;
}

function addDays(from: Date, days: number): Date {
    const shifted = new Date(from);
    shifted.setUTCDate(shifted.getUTCDate() + days);
    return shifted;
}

export const VALID_TRIAGE_STATUSES: readonly string[] = [TRIAGE_UNDER_REVIEW, TRIAGE_AFFECTED, TRIAGE_NOT_AFFECTED, TRIAGE_FIXED];

/**
 * The VEX justifications for a `not_affected` statement, per the OpenVEX / CSAF
 * vocabulary.
 *
 * Kept as the canonical list so that a VEX document can be produced from these rows
 * without re-translating free text. That is the whole reason triage is stored in the
 * standard's vocabulary.
 */
export const VEX_JUSTIFICATIONS: readonly string[] = [
    'component_not_present',
    'vulnerable_code_not_present',
    'vulnerable_code_not_in_execute_path',
    'vulnerable_code_cannot_be_controlled_by_adversary',
    'inline_mitigations_already_exist'
];
