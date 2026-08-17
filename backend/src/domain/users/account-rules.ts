import { ADMIN_ROLES, VALID_ROLES } from './roles';

/**
 * The rules that stop an administrator from locking themselves out.
 *
 * They live here, pure, because they are rules and not queries: each describes a situation
 * where the UI would happily accept an action nobody could come back from. There is no
 * rescue screen in Zanshin — no remaining
 * administrateur actif, et il faut une session psql.
 */

export const MINIMUM_PASSWORD_LENGTH = 12;

const USERNAME = /^[A-Za-z0-9._-]{2,64}$/;

export function isAdminRole(role: string): boolean {
    return (ADMIN_ROLES as readonly string[]).includes(role);
}

/** `null` if the name is acceptable, otherwise the message to show. */
export function validateUsername(username: string): string | null {
    if (!username) return "L'identifiant est requis.";
    if (!USERNAME.test(username)) {
        return 'Invalid username: 2 to 64 characters, letters, digits, ". _ -".';
    }
    return null;
}

/**
 * `null` si le mot de passe est acceptable.
 *
 * A minimum length and nothing else — no composition rule. Character-class requirements
 * produce `Password1!` and encourage reuse; length is the only constraint whose effect on
 * entropy is real.
 */
export function validatePassword(password: string): string | null {
    if (!password) return 'Le mot de passe est requis.';
    if (password.length < MINIMUM_PASSWORD_LENGTH) {
        return `The password must be at least ${MINIMUM_PASSWORD_LENGTH} characters.`;
    }
    // bcrypt truncates at 72 bytes: past that, the extra characters protect nothing, and
    // letting someone believe otherwise would be worse than refusing.
    if (Buffer.byteLength(password, 'utf8') > 72) {
        return 'The password exceeds 72 bytes, past which bcrypt ignores the rest.';
    }
    return null;
}

export function validateRole(role: string): string | null {
    return (VALID_ROLES as readonly string[]).includes(role)
        ? null
        : `Unknown role "${role}". Expected ${VALID_ROLES.join(', ')}.`;
}

/**
 * `null` if the change is allowed, otherwise why it is refused.
 *
 * `remainingActiveAdmins` compte les administrateurs actifs **autres que celui-ci**.
 * Refused at the account level rather than the screen's: three tabs open on two accounts
 * would otherwise be enough to empty the administrator list.
 */
export function refuseSelfLockout(options: {
    isSelf: boolean;
    wasAdmin: boolean;
    willBeAdmin: boolean;
    willBeActive: boolean;
    remainingActiveAdmins: number;
}): string | null {
    const { isSelf, wasAdmin, willBeAdmin, willBeActive, remainingActiveAdmins } = options;

    if (isSelf && !willBeActive) return 'You cannot deactivate your own account.';
    if (isSelf && wasAdmin && !willBeAdmin) return 'You cannot remove your own administrator role.';

    const losesAdmin = wasAdmin && (!willBeAdmin || !willBeActive);
    if (losesAdmin && remainingActiveAdmins === 0) {
        return "C'est le dernier administrateur actif : le retirer laisserait Zanshin sans personne pour administrer.";
    }
    return null;
}

/** Likewise for deletion, whose consequences are the same but worse. */
export function refuseDeletion(options: { isSelf: boolean; isAdmin: boolean; remainingActiveAdmins: number }): string | null {
    if (options.isSelf) return 'Vous ne pouvez pas supprimer votre propre compte.';
    if (options.isAdmin && options.remainingActiveAdmins === 0) {
        return "C'est le dernier administrateur actif : le supprimer laisserait Zanshin sans personne pour administrer.";
    }
    return null;
}
