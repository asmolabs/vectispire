import { GatePolicyRow } from '../persistence/entities';
import type { StoredPolicy } from '../domain/gate/policy-resolution';

/**
 * Les politiques de gate, indexées par portée.
 *
 * Posées dans la couche dépôts et non dans un contrôleur : **deux appelants en ont
 * besoin** — l'API du gate, et le balayage qui ouvre les tickets. Les laisser dans le
 * contrôleur obligerait le service à importer la couche HTTP, ce que l'ordre des couches
 * interdit et pour une bonne raison : la résolution d'une politique n'a rien à voir avec
 * une requête.
 */

export function indexPolicies(rows: GatePolicyRow[]): Map<string, StoredPolicy> {
    const byScope = new Map<string, StoredPolicy>();
    for (const row of rows) byScope.set(`${row.targetKind}:${row.targetId}`, toStoredPolicy(row));
    return byScope;
}

export function toStoredPolicy(row: GatePolicyRow): StoredPolicy {
    return {
        failOnSeverity: row.failOnSeverity,
        failOnKev: row.failOnKev,
        fixableOnly: row.fixableOnly,
        includeTriaged: row.includeTriaged,
        includeAiReview: row.includeAiReview,
        version: row.version
    };
}
