import type { ApiKeyTargets, SolutionTree, TargetGrant } from '../core/api.models';

/** A target as the access pickers hold it: `kind:id`, so one list spans every kind. */
export interface GrantOption {
    label: string;
    value: string;
}

/** The word for each kind, already translated by the screen that owns the picker. */
export interface GrantKindLabels {
    repository: string;
    container: string;
    project: string;
}

/** A list from the server, or none: read inside a computed the template renders, anything else would break the screen. */
const listOf = <T>(rows: T[] | null | undefined): T[] => (Array.isArray(rows) ? rows : []);

/**
 * Everything the users and teams dialogs can grant, and everything already granted.
 *
 * Repositories and images come from the API-key target list, projects from the solutions tree,
 * each labelled "Solution / Project" as the server names a project grant.
 *
 * **A grant already held is always an option, labelled with the name the server sent.** The picker
 * renders a selected value only if an option carries it: a grant on something the lists do not hold
 * — a project the tree failed to load, a kind this screen does not know — would otherwise show as
 * nothing ticked, and saving the dialog as shown would revoke it without anybody deciding to.
 */
export function grantOptions(
    targets: ApiKeyTargets | null,
    tree: SolutionTree | null,
    granted: TargetGrant[],
    labels: GrantKindLabels
): GrantOption[] {
    const word = (kind: string): string =>
        kind === 'repository' || kind === 'container' || kind === 'project' ? labels[kind] : kind;

    const options: GrantOption[] = [
        ...listOf(targets?.repositories).map((row) => ({
            label: `${labels.repository} — ${row.label}`,
            value: `repository:${row.id}`
        })),
        ...listOf(targets?.containers).map((row) => ({
            label: `${labels.container} — ${row.label}`,
            value: `container:${row.id}`
        })),
        ...listOf(tree?.solutions).flatMap((solution) =>
            listOf(solution.projects).map((project) => ({
                label: `${labels.project} — ${solution.name} / ${project.name}`,
                value: `project:${project.id}`
            }))
        )
    ];

    const byValue = new Map(options.map((option) => [option.value, option]));
    for (const grant of listOf(granted)) {
        const value = `${grant.kind}:${grant.id}`;
        const label = `${word(grant.kind)} — ${grant.name ?? grant.id}`;
        const known = byValue.get(value);
        if (known) {
            known.label = label;
        } else {
            const option = { label, value };
            options.push(option);
            byValue.set(value, option);
        }
    }
    return options;
}
