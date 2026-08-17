/**
 * The vocabulary of roles.
 *
 * It lives in the domain and not in the entity: it is a business rule, not a column.
 * `user.entity.ts` re-exports it so as not to break callers, but the definition is here —
 * the layering rule forbids `domain/` from knowing `persistence/`, and it is right: the
 * roles would still exist if Zanshin changed database.
 */
export const ADMIN_ROLES = ['SUPERUSER', 'ADMIN'] as const;
export const VALID_ROLES = ['SUPERUSER', 'ADMIN', 'USER'] as const;
