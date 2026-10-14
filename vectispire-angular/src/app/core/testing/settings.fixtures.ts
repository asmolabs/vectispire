import type { TicketTokenState } from '../api.models';

/**
 * The tracker token's state as `GET /api/v1/settings/ticket-token` sends it: what a case does not
 * set is unknown, which the server writes as null. The specs sent `{ configured, expirySource }`
 * alone, and four fields the screen reads arrived `undefined`, a value no server sends.
 */
export function ticketTokenState(changes: Partial<TicketTokenState> = {}): TicketTokenState {
    return {
        configured: false,
        expiresAt: null,
        expirySource: 'unknown',
        refusedStatus: null,
        refusedSince: null,
        checkedAt: null,
        ...changes
    };
}
