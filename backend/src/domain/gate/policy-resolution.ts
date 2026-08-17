import { BUILT_IN_POLICY, GatePolicy, RequestedPolicy, harden } from './policy-gate';

/**
 * Which policy applies to a target, and **where it comes from**.
 *
 * The provenance is part of the answer, not debugging information: a pipeline that fails
 * needs to know whether these are its own rules, its target's, or the organization's
 * default — otherwise the first reflex is to loosen its own settings, which then changes
 * nothing.
 */

export const SOURCE_TARGET = 'target';
export const SOURCE_GLOBAL = 'global';
export const SOURCE_BUILT_IN = 'built-in';

export type PolicySource = typeof SOURCE_TARGET | typeof SOURCE_GLOBAL | typeof SOURCE_BUILT_IN;

/** A policy as it is stored, reduced to what the resolution looks at. */
export interface StoredPolicy extends GatePolicy {
    version: number;
}

export interface ResolvedPolicy {
    policy: GatePolicy;
    source: PolicySource;
    version: number | null;
    /** The fields the request asked to loosen and did not get. */
    ignoredRelaxations: string[];
}

export interface PolicyLookup {
    /** The target's active policy, or `null`. */
    forTarget: StoredPolicy | null;
    /** The active global policy, or `null`. */
    global: StoredPolicy | null;
}

/**
 * Target, then global, then built-in.
 *
 * **A target's policy replaces the global one entirely**, it does not merge with it. A
 * half-inherited policy is impossible to reason about when a build fails, and "this
 * repository's rules" must be readable in one single place.
 *
 * `requested` carries what the caller actually sent, and can only **tighten**: without
 * that, any pipeline would turn whatever it liked green from its own request body. Refused
 * relaxations are reported back rather than ignored silently.
 */
export function resolvePolicy(lookup: PolicyLookup, requested?: RequestedPolicy, scoped = true): ResolvedPolicy {
    let stored: StoredPolicy | null = null;
    let source: PolicySource;

    if (scoped) {
        // A request for a target: its own first, the global one next.
        stored = lookup.forTarget;
        source = SOURCE_TARGET;
        if (stored === null) {
            stored = lookup.global;
            source = SOURCE_GLOBAL;
        }
    } else {
        // A request on the global scope: that policy, and nothing else.
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

/** What a pipeline reads when its verdict surprises it. */
export function describeSource(resolved: Pick<ResolvedPolicy, 'source' | 'version'>): string {
    if (resolved.source === SOURCE_BUILT_IN) return "the application's default policy";
    const scope = resolved.source === SOURCE_TARGET ? "the target's" : 'the global';
    return `${scope} policy v${resolved.version}`;
}
