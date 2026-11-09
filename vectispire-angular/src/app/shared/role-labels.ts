import type { I18nService } from '../core/i18n/i18n.service';
import { keyFor } from '../core/i18n/literal-keys';

/**
 * The server's roles. The document types `role` as a plain string, so the union is written here, in
 * the order of `ROLES` in `core/testing/contract.ts`, which checks it against the document.
 */
export type Role = 'SUPERUSER' | 'ADMIN' | 'CISO' | 'SECURITY_CHAMPION' | 'AUDITOR' | 'USER';

/**
 * A role in the words the accounts screen uses, through literal keys (decision 0019): the refusal
 * page built `roles.${role.toLowerCase()}` and compared the answer with the key to detect a miss —
 * a check the i18n script could not see, on the one page that tells somebody what they are.
 */
export const ROLE_KEYS = {
    SUPERUSER: 'roles.superuser',
    ADMIN: 'roles.admin',
    CISO: 'roles.ciso',
    SECURITY_CHAMPION: 'roles.security_champion',
    AUDITOR: 'roles.auditor',
    USER: 'roles.user'
} as const satisfies Record<Role, string>;

/** A role this client does not know is shown as the server named it — never as a key path. */
export function roleLabel(i18n: I18nService, role: string): string {
    const key = keyFor(ROLE_KEYS, role);
    return key ? i18n.t(key) : role;
}
