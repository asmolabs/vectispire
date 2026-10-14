import type { AuthenticatedUser } from '../api.models';

/**
 * The account a session is opened for, whole.
 *
 * <p>Twelve specs opened a session with `{ id: 1, username: 'x', role, mustChangePassword: false } as never`:
 * the cast hid that `UserSummary` has no `id` and that `mfaEnabled` and `displayName` were missing, so
 * a screen that came to read either would have been tested against a user the server never sends.
 */
export function sessionUser(role: string, changes: Partial<AuthenticatedUser> = {}): AuthenticatedUser {
    return { username: 'x', displayName: null, role, mustChangePassword: false, mfaEnabled: false, ...changes };
}
