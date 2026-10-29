import { afterNextRender, computed, inject, Injectable, Injector, signal } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { forkJoin } from 'rxjs';
import { messageOf } from '../../core/api-error';
import { PluginsApi } from '../../core/api/plugins.api';
import { SolutionsApi } from '../../core/api/solutions.api';
import type {
    ContainerRef,
    OpenIssues,
    Plugin,
    PluginActivation,
    ProjectNode,
    RepositoryRef,
    SolutionNode,
    SolutionTree
} from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { LatestRequest } from '../../core/latest-request';
import { SessionStore } from '../../core/session.store';
import { SEVERITY_TONES, type SeverityTone } from '../../shared/severity';

/** How a plugin's declared languages meet a project's detected ones. */
export interface PluginFit {
    matched: ReadonlySet<string>;
    verdict: 'present' | 'absent' | 'absent_so_far';
    list: string;
}

// Defensive on purpose: a control plane from before the count sends neither field, and that is
// "unknown", not a crash of the whole tree.
export function languagesOf(project: ProjectNode): readonly string[] {
    const languages: readonly string[] | undefined = project.detectedLanguages;
    return languages ?? [];
}

export function unknownFor(project: ProjectNode): readonly number[] {
    const ids: readonly number[] | undefined = project.languagesUnknownFor;
    return ids ?? [];
}

/** The server's limits (decision 0023), enforced in the form so a long name is stopped as it is typed. */
export const NAME_MAX = 100;
export const DESCRIPTION_MAX = 255;

export type Severity = Exclude<keyof OpenIssues, 'total'>;

/** What the name-and-description dialog is editing. */
export type Editing =
    | { kind: 'solution'; solution: SolutionNode | null }
    | { kind: 'project'; solution: SolutionNode; project: ProjectNode | null };

/**
 * What a project holds: a repository or a container image. The kind travels with the reference
 * because the two have separate routes and separate numbering — repository 42 and image 42 are two
 * targets, and filing one through the other's route would move the wrong thing.
 */
export type Filed = { kind: 'repository'; ref: RepositoryRef } | { kind: 'container'; ref: ContainerRef };

/** The three changes that take something away from somebody, and so are confirmed first. */
export type Pending =
    | { kind: 'delete-solution'; solution: SolutionNode }
    | { kind: 'delete-project'; solution: SolutionNode; project: ProjectNode }
    | { kind: 'unfile'; target: Filed; solution: SolutionNode; project: ProjectNode };

/** The repository or image being filed, and the project it is in today, if any. */
export interface Filing {
    target: Filed;
    from: { solution: SolutionNode; project: ProjectNode } | null;
}

/**
 * The tree the solutions screen shows, and what each of its dialogs is open on, shared by the
 * components the screen is made of and provided by `Solutions`, so each visit starts from nothing.
 *
 * **Every account reads it, and reads only what it may see.** The server builds the tree over the
 * reader's visibility, so a project seen through one granted repository out of three is marked
 * `partial` — and the screen says so in words, beside the figures.
 *
 * The tree's buttons open a dialog here — the node edited, the change to confirm, the target to file,
 * the project to move or whose plugins to show — and each dialog makes its own write, then reloads
 * the tree through {@link reload}. `formError` and `saving` are shared: one dialog is open at a time.
 */
@Injectable()
export class SolutionsPage {
    private readonly api = inject(SolutionsApi);
    private readonly pluginsApi = inject(PluginsApi);
    private readonly i18n = inject(I18nService);
    private readonly session = inject(SessionStore);
    private readonly injector = inject(Injector);
    private readonly load = new LatestRequest();

    readonly isAdmin = this.session.isAdmin;
    /** Which plugins a project runs is governance: read by its readers, changed by a security lead. */
    readonly readsGovernance = this.session.canReadGovernance;
    readonly isSecurityLead = this.session.isSecurityLead;
    readonly languagesOf = languagesOf;
    readonly nameMax = NAME_MAX;
    readonly descriptionMax = DESCRIPTION_MAX;

    readonly tree = signal<SolutionTree | null>(null);
    readonly loading = signal(true);
    readonly saving = signal(false);
    readonly error = signal<string | null>(null);
    readonly formError = signal<string | null>(null);
    readonly notice = signal<string | null>(null);

    /** The project a link from the repository list points at, highlighted once the tree is drawn. */
    readonly focused = signal<string | null>(inject(ActivatedRoute).snapshot.fragment ?? null);

    readonly solutions = computed(() => this.tree()?.solutions ?? []);
    readonly unfiled = computed(() => this.tree()?.unfiled ?? null);
    readonly hasProjects = computed(() => this.solutions().some((solution) => (solution.projects ?? []).length > 0));

    /**
     * The severities, worst first, with their label. Literal keys, so the i18n check sees each one
     * and a severity cannot ship as a raw key.
     */
    readonly severities = computed<{ field: Severity; label: string; colour: SeverityTone }[]>(() => {
        this.i18n.translations();
        return [
            { field: 'critical', label: this.i18n.t('severities.critical'), colour: SEVERITY_TONES.critical },
            { field: 'high', label: this.i18n.t('severities.high'), colour: SEVERITY_TONES.high },
            { field: 'medium', label: this.i18n.t('severities.medium'), colour: SEVERITY_TONES.medium },
            { field: 'low', label: this.i18n.t('severities.low'), colour: SEVERITY_TONES.low },
            { field: 'negligible', label: this.i18n.t('severities.negligible'), colour: SEVERITY_TONES.negligible },
            { field: 'unknown', label: this.i18n.t('severities.unknown'), colour: SEVERITY_TONES.unknown }
        ];
    });

    // --- The name-and-description dialog ---------------------------------------------------------

    readonly editing = signal<Editing | null>(null);
    readonly editorVisible = signal(false);
    readonly formName = signal('');
    readonly formDescription = signal('');

    // --- Confirmations -------------------------------------------------------------------------

    readonly pending = signal<Pending | null>(null);
    readonly confirmVisible = signal(false);

    // --- Filing ---------------------------------------------------------------------------------

    readonly filing = signal<Filing | null>(null);
    readonly fileVisible = signal(false);
    readonly targetProjectId = signal<number | null>(null);

    // --- Moving a project ---------------------------------------------------------------------------

    readonly moving = signal<{ solution: SolutionNode; project: ProjectNode } | null>(null);
    readonly moveVisible = signal(false);
    readonly targetSolutionId = signal<number | null>(null);
    readonly moveName = signal('');
    readonly moveNameTaken = signal<string | null>(null);

    // --- Plugins switched on for a project (decision 0017) -----------------------------------------

    readonly pluginsProject = signal<{ solution: SolutionNode; project: ProjectNode } | null>(null);
    readonly pluginsVisible = signal(false);
    readonly registry = signal<Plugin[] | null>(null);
    readonly activations = signal<Map<string, PluginActivation>>(new Map());
    readonly pluginsError = signal<string | null>(null);
    readonly pluginBusy = signal<string | null>(null);
    private readonly pluginsLoad = new LatestRequest();

    constructor() {
        this.reload();
    }

    /**
     * The registry beside the project's activations, so every plugin is offered — switched on or not
     * — with the languages it would look for. A plugin disabled on the platform keeps its activation
     * and runs nowhere; the dialog says so rather than let a switch that is on read as "running".
     */
    openPlugins(solution: SolutionNode, project: ProjectNode): void {
        this.pluginsProject.set({ solution, project });
        this.registry.set(null);
        this.activations.set(new Map());
        this.pluginsError.set(null);
        this.pluginsVisible.set(true);
        this.pluginsLoad.run(
            forkJoin({ plugins: this.pluginsApi.plugins(), active: this.pluginsApi.projectPlugins(project.id) }),
            {
                next: ({ plugins, active }) => {
                    this.registry.set(plugins);
                    this.activations.set(new Map(active.map((activation) => [activation.pluginId, activation])));
                },
                error: (failure) => {
                    this.registry.set([]);
                    this.pluginsError.set(messageOf(failure, this.i18n.t('solutions.plugins_error_load')));
                }
            }
        );
    }

    reload(preserveError = false): void {
        this.loading.set(true);
        this.load.run(this.api.solutionTree(), {
            next: (tree) => {
                this.tree.set(tree ?? null);
                if (!preserveError) this.error.set(null);
                this.loading.set(false);
                this.scrollToFocused();
            },
            error: (failure) => {
                this.error.set(messageOf(failure, this.i18n.t('solutions.error_load')));
                this.loading.set(false);
            }
        });
    }

    // --- Create, rename -------------------------------------------------------------------------

    newSolution(): void {
        this.openEditor({ kind: 'solution', solution: null }, '', '');
    }

    editSolution(solution: SolutionNode): void {
        this.openEditor({ kind: 'solution', solution }, solution.name, solution.description ?? '');
    }

    newProject(solution: SolutionNode): void {
        this.openEditor({ kind: 'project', solution, project: null }, '', '');
    }

    editProject(solution: SolutionNode, project: ProjectNode): void {
        this.openEditor({ kind: 'project', solution, project }, project.name, project.description ?? '');
    }

    private openEditor(editing: Editing, name: string, description: string): void {
        this.editing.set(editing);
        this.formName.set(name);
        this.formDescription.set(description);
        this.formError.set(null);
        this.editorVisible.set(true);
    }

    // --- Delete, remove -------------------------------------------------------------------------

    askDeleteSolution(solution: SolutionNode): void {
        this.ask({ kind: 'delete-solution', solution });
    }

    askDeleteProject(solution: SolutionNode, project: ProjectNode): void {
        this.ask({ kind: 'delete-project', solution, project });
    }

    askUnfile(target: Filed, solution: SolutionNode, project: ProjectNode): void {
        this.ask({ kind: 'unfile', target, solution, project });
    }

    private ask(pending: Pending): void {
        this.pending.set(pending);
        this.confirmVisible.set(true);
    }

    // --- File, move -----------------------------------------------------------------------------

    openFile(target: Filed, from: { solution: SolutionNode; project: ProjectNode } | null = null): void {
        this.filing.set({ target, from });
        this.targetProjectId.set(null);
        this.formError.set(null);
        this.fileVisible.set(true);
    }

    // --- Move a project to another solution --------------------------------------------------------

    openMoveProject(solution: SolutionNode, project: ProjectNode): void {
        this.moving.set({ solution, project });
        this.targetSolutionId.set(null);
        this.moveName.set('');
        this.moveNameTaken.set(null);
        this.formError.set(null);
        this.moveVisible.set(true);
    }

    projectPath(projectId: number | null): string | null {
        if (projectId === null) return null;
        for (const solution of this.solutions()) {
            const project = (solution.projects ?? []).find((candidate) => candidate.id === projectId);
            if (project) return pathOf(solution, project);
        }
        return null;
    }

    /**
     * The repository list links to `/solutions#project-<id>`. The router's anchor scrolling runs at
     * navigation, before the tree has arrived, so the scroll is made again once it is drawn.
     */
    private scrollToFocused(): void {
        const anchor = this.focused();
        if (!anchor) return;
        afterNextRender(() => document.getElementById(anchor)?.scrollIntoView?.({ block: 'center' }), {
            injector: this.injector
        });
    }
}

export const PROJECT_NAME_TAKEN = 'urn:vectispire:problem:project-name-taken';
export const SOLUTION_NAME_TAKEN = 'urn:vectispire:problem:solution-name-taken';

/** The RFC 7807 `type` of a refusal, so a refusal the screen can answer is told from one it can only show. */
export function problemType(failure: unknown): unknown {
    return (failure as { error?: { type?: unknown } } | null)?.error?.type;
}

/** "Solution / Project" — how the server names a project in a grant, and so how this screen does. */
export function pathOf(solution: SolutionNode, project: ProjectNode): string {
    return `${solution.name} / ${project.name}`;
}
