import { BUILT_IN_POLICY, GatePolicy, RequestedPolicy, harden } from './policy-gate';

/**
 * Quelle politique s'applique à une cible, et **d'où elle vient**.
 *
 * La provenance fait partie de la réponse, ce n'est pas une information de mise au
 * point : un pipeline qui échoue a besoin de savoir si ce sont ses propres règles,
 * celles de sa cible, ou le défaut de l'organisation — sans quoi le premier réflexe est
 * d'élargir ses propres réglages, ce qui ne change alors rien.
 */

export const SOURCE_TARGET = 'target';
export const SOURCE_GLOBAL = 'global';
export const SOURCE_BUILT_IN = 'built-in';

export type PolicySource = typeof SOURCE_TARGET | typeof SOURCE_GLOBAL | typeof SOURCE_BUILT_IN;

/** Une politique telle qu'elle est stockée, réduite à ce que la résolution regarde. */
export interface StoredPolicy extends GatePolicy {
    version: number;
}

export interface ResolvedPolicy {
    policy: GatePolicy;
    source: PolicySource;
    version: number | null;
    /** Les champs que la requête a demandé d'assouplir et n'a pas obtenus. */
    ignoredRelaxations: string[];
}

export interface PolicyLookup {
    /** La politique active de la cible, ou `null`. */
    forTarget: StoredPolicy | null;
    /** La politique active globale, ou `null`. */
    global: StoredPolicy | null;
}

/**
 * Cible, puis globale, puis intégrée.
 *
 * **Une politique de cible remplace entièrement la globale**, elle ne fusionne pas avec
 * elle. Une politique à moitié héritée est impossible à raisonner quand une compilation
 * échoue, et « les règles de ce dépôt » doit se lire à un seul endroit.
 *
 * `requested` porte ce que l'appelant a réellement envoyé, et ne peut que **durcir** :
 * sans cela, n'importe quel pipeline rendrait vert ce qu'il veut depuis le corps de sa
 * requête. Les assouplissements refusés lui sont renvoyés plutôt qu'ignorés en silence.
 */
export function resolvePolicy(lookup: PolicyLookup, requested?: RequestedPolicy, scoped = true): ResolvedPolicy {
    let stored: StoredPolicy | null = null;
    let source: PolicySource;

    if (scoped) {
        // Demande pour une cible : la sienne d'abord, la globale ensuite.
        stored = lookup.forTarget;
        source = SOURCE_TARGET;
        if (stored === null) {
            stored = lookup.global;
            source = SOURCE_GLOBAL;
        }
    } else {
        // Demande sur la portée globale : sa politique, et rien d'autre.
        stored = lookup.global;
        source = SOURCE_GLOBAL;
    }

    let base: GatePolicy;
    let version: number | null = null;
    if (stored === null) {
        base = BUILT_IN_POLICY;
        source = SOURCE_BUILT_IN;
    } else {
        const { version: storedVersion, ...policy } = stored;
        base = policy;
        version = storedVersion;
    }

    if (!requested) return { policy: base, source, version, ignoredRelaxations: [] };

    const { policy, ignoredRelaxations } = harden(base, requested);
    return { policy, source, version, ignoredRelaxations };
}

/** Ce qu'un pipeline lit quand son verdict le surprend. */
export function describeSource(resolved: Pick<ResolvedPolicy, 'source' | 'version'>): string {
    if (resolved.source === SOURCE_BUILT_IN) return "politique par défaut de l'application";
    const scope = resolved.source === SOURCE_TARGET ? 'de la cible' : 'globale';
    return `politique ${scope} v${resolved.version}`;
}
