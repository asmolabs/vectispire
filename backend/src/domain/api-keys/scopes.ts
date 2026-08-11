/**
 * Le vocabulaire des portées d'une clé d'API.
 *
 * Défini dans le domaine et réexporté par l'entité, pour la même raison que les rôles :
 * c'est une règle métier, pas une colonne.
 */
export const SCOPE_READ = 'read';
export const SCOPE_SCAN = 'scan';
export const SCOPE_EXPORT = 'export';
export const SCOPE_AGENT = 'agent';

export const ALL_SCOPES = [SCOPE_READ, SCOPE_SCAN, SCOPE_EXPORT, SCOPE_AGENT] as const;

/** `agent` n'est **jamais** implicite : ce périmètre donne le droit d'exécuter des scans. */
export const DEFAULT_SCOPES = [SCOPE_READ, SCOPE_SCAN, SCOPE_EXPORT] as const;
