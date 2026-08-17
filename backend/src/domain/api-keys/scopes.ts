/**
 * The vocabulary of an API key's scopes.
 *
 * Defined in the domain and re-exported by the entity, for the same reason as the roles: it
 * is a business rule, not a column.
 */
export const SCOPE_READ = 'read';
export const SCOPE_SCAN = 'scan';
export const SCOPE_EXPORT = 'export';
export const SCOPE_AGENT = 'agent';

export const ALL_SCOPES = [SCOPE_READ, SCOPE_SCAN, SCOPE_EXPORT, SCOPE_AGENT] as const;

/** `agent` is **never** implicit: that scope grants the right to run scans. */
export const DEFAULT_SCOPES = [SCOPE_READ, SCOPE_SCAN, SCOPE_EXPORT] as const;
