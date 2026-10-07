import type { Params } from '@angular/router';
import type { OwaspScopeQuery, SolutionTree } from '@/app/core/api.models';
import type { I18nService } from '@/app/core/i18n/i18n.service';

/**
 * The project or solution an OWASP view is read over, apart from any screen.
 *
 * Both views of the OWASP page — the grid as it stands and the grid week by week — take the same
 * scope from the same two query parameters, so that switching from one to the other keeps it and a
 * link to either reproduces it. Written once: two readers of `project_id` with their own idea of
 * which one wins when a link carries both would show two different estates under one URL.
 *
 * No repository: the product owner's choice, and the server's — neither route takes one.
 */
export type OwaspScope = { kind: 'project' | 'solution'; id: number } | null;

/** A positive integer, or nothing: a garbled id in a link is dropped rather than sent for a 400. */
function idOf(value: string | null): number | null {
    if (value === null || !/^\d+$/.test(value)) return null;
    const id = Number(value);
    return id > 0 ? id : null;
}

/** The scope a URL names. The server refuses both; a link carrying both keeps the narrower one. */
export function readScope(params: { get(name: string): string | null }): OwaspScope {
    const projectId = idOf(params.get('project_id'));
    if (projectId !== null) return { kind: 'project', id: projectId };
    const solutionId = idOf(params.get('solution_id'));
    return solutionId !== null ? { kind: 'solution', id: solutionId } : null;
}

/**
 * The scope as query parameters — of the view's own URL and of every link leaving it, since the
 * backlog reads the same two names. Nothing for the estate, so a plain visit stays a plain URL.
 */
export function scopeParams(scope: OwaspScope): Params {
    return scope ? { [`${scope.kind}_id`]: String(scope.id) } : {};
}

/** What the server is asked: nothing for the estate, never both. */
export function scopeQuery(scope: OwaspScope): OwaspScopeQuery {
    if (scope?.kind === 'project') return { project_id: scope.id };
    if (scope?.kind === 'solution') return { solution_id: scope.id };
    return {};
}

export function sameScope(a: OwaspScope, b: OwaspScope): boolean {
    return a === b || (a !== null && b !== null && a.kind === b.kind && a.id === b.id);
}

/** The picker's value for a scope: one string, because a select compares its options by identity. */
export function scopeValue(scope: OwaspScope): string {
    return scope ? `${scope.kind}:${scope.id}` : 'estate';
}

/** The scope a picker's value names; anything it does not recognise is the estate. */
export function scopeOfValue(value: string | null): OwaspScope {
    const [kind, raw] = (value ?? 'estate').split(':');
    const id = idOf(raw ?? null);
    return (kind === 'project' || kind === 'solution') && id !== null ? { kind, id } : null;
}

export interface ScopeOption {
    value: string;
    label: string;
}

/**
 * The estate, then every solution followed by its projects — the tree's own order, so a project
 * is read under the solution it belongs to. A tree that failed to load leaves the estate alone,
 * which is still a view.
 */
export function scopeOptions(i18n: I18nService, tree: SolutionTree | null): ScopeOption[] {
    const options: ScopeOption[] = [{ value: 'estate', label: i18n.t('owasp_weekly.scope_estate') }];
    for (const solution of tree?.solutions ?? []) {
        options.push({
            value: `solution:${solution.id}`,
            label: i18n.t('owasp_weekly.scope_solution', { name: solution.name })
        });
        for (const project of solution.projects ?? []) {
            options.push({
                value: `project:${project.id}`,
                label: i18n.t('owasp_weekly.scope_project', { name: `${solution.name} / ${project.name}` })
            });
        }
    }
    return options;
}
