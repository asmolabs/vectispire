import { DatePipe, NgTemplateOutlet } from '@angular/common';
import { ChangeDetectionStrategy, Component, Injector, afterNextRender, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { Observable } from 'rxjs';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { TagModule } from '@openng/optimus-ui/tag';
import { ToggleSwitchModule } from '@openng/optimus-ui/toggleswitch';
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
    Schema,
    SolutionNode,
    SolutionTree
} from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { LatestRequest } from '../../core/latest-request';
import { SessionStore } from '../../core/session.store';
import { DetectedLanguages } from '../../shared/detected-languages';

/** How a plugin's declared languages meet a project's detected ones. */
interface PluginFit {
    matched: ReadonlySet<string>;
    verdict: 'present' | 'absent' | 'absent_so_far';
    list: string;
}

// Defensive on purpose: a control plane from before the count sends neither field, and that is
// "unknown", not a crash of the whole tree.
function languagesOf(project: ProjectNode): readonly string[] {
    const languages: readonly string[] | undefined = project.detectedLanguages;
    return languages ?? [];
}

function unknownFor(project: ProjectNode): readonly number[] {
    const ids: readonly number[] | undefined = project.languagesUnknownFor;
    return ids ?? [];
}

/** The server's limits (decision 0023), enforced in the form so a long name is stopped as it is typed. */
export const NAME_MAX = 100;
export const DESCRIPTION_MAX = 255;

type Severity = Exclude<keyof OpenIssues, 'total'>;

/** What the name-and-description dialog is editing. */
type Editing =
    | { kind: 'solution'; solution: SolutionNode | null }
    | { kind: 'project'; solution: SolutionNode; project: ProjectNode | null };

/**
 * What a project holds: a repository or a container image. The kind travels with the reference
 * because the two have separate routes and separate numbering — repository 42 and image 42 are two
 * targets, and filing one through the other's route would move the wrong thing.
 */
export type Filed = { kind: 'repository'; ref: RepositoryRef } | { kind: 'container'; ref: ContainerRef };

/** The three changes that take something away from somebody, and so are confirmed first. */
type Pending =
    | { kind: 'delete-solution'; solution: SolutionNode }
    | { kind: 'delete-project'; solution: SolutionNode; project: ProjectNode }
    | { kind: 'unfile'; target: Filed; solution: SolutionNode; project: ProjectNode };

/** The repository or image being filed, and the project it is in today, if any. */
interface Filing {
    target: Filed;
    from: { solution: SolutionNode; project: ProjectNode } | null;
}

/**
 * Solutions → projects → repositories and container images (decision 0023 and its amendment).
 *
 * **Every account reads it, and reads only what it may see.** The server builds the tree over the
 * reader's visibility, so a project seen through one granted repository out of three is marked
 * `partial` — and the screen says so in words, beside the figures, because half a project presented
 * as the whole of it is a wrong figure that looks right.
 *
 * **"No project" is always shown, at the end, empty or not.** A filing that is not finished must
 * look unfinished; a group that vanished when empty would also vanish from the reader's mind.
 *
 * **Filing is an access change.** A grant on a project covers what the project holds at the time of
 * each request, so moving a repository takes it from one project's holders and gives it to the
 * other's. The dialogs say so before the click, not the audit log after it.
 *
 * The write actions follow `isAdmin`; the server is the authority, and a refusal it sends is shown
 * as it sends it.
 */
@Component({
    selector: 'app-solutions',
    imports: [
        DatePipe,
        NgTemplateOutlet,
        FormsModule,
        RouterLink,
        ButtonModule,
        CardModule,
        DialogModule,
        InputTextModule,
        MessageModule,
        SelectModule,
        TagModule,
        ToggleSwitchModule,
        TranslatePipe,
        DetectedLanguages
    ],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './solutions.html'
})
export class Solutions {
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
    readonly severities = computed<
        { field: Severity; label: string; colour: 'danger' | 'warn' | 'info' | 'secondary' }[]
    >(() => {
        this.i18n.translations();
        return [
            { field: 'critical', label: this.i18n.t('severities.critical'), colour: 'danger' },
            { field: 'high', label: this.i18n.t('severities.high'), colour: 'danger' },
            { field: 'medium', label: this.i18n.t('severities.medium'), colour: 'warn' },
            { field: 'low', label: this.i18n.t('severities.low'), colour: 'info' },
            { field: 'negligible', label: this.i18n.t('severities.negligible'), colour: 'secondary' },
            { field: 'unknown', label: this.i18n.t('severities.unknown'), colour: 'secondary' }
        ];
    });

    // --- The name-and-description dialog ---------------------------------------------------------

    readonly editing = signal<Editing | null>(null);
    readonly editorVisible = signal(false);
    readonly formName = signal('');
    readonly formDescription = signal('');

    readonly editorHeader = computed(() => {
        this.i18n.translations();
        const editing = this.editing();
        if (!editing) return '';
        if (editing.kind === 'solution') {
            return editing.solution
                ? this.i18n.t('solutions.header_edit_solution')
                : this.i18n.t('solutions.header_new_solution');
        }
        return editing.project
            ? this.i18n.t('solutions.header_edit_project')
            : this.i18n.t('solutions.header_new_project', { solution: editing.solution.name });
    });

    // --- Confirmations -------------------------------------------------------------------------

    readonly pending = signal<Pending | null>(null);
    readonly confirmVisible = signal(false);

    /**
     * What the confirmation says, in full. Deleting a project detaches its repositories **and**
     * revokes the grants naming it — the two consequences an administrator would otherwise learn
     * from the account that stopped seeing something.
     */
    readonly confirmText = computed(() => {
        this.i18n.translations();
        const pending = this.pending();
        if (!pending) return '';
        switch (pending.kind) {
            case 'delete-solution':
                return this.i18n.t('solutions.delete_solution_consequence', { name: pending.solution.name });
            case 'delete-project':
                return this.i18n.t('solutions.delete_project_consequence', {
                    name: pathOf(pending.solution, pending.project),
                    count: pending.project.repositoryCount,
                    images: pending.project.containerCount
                });
            case 'unfile':
                return this.i18n.t('solutions.unfile_consequence', {
                    target: pending.target.ref.name,
                    project: pathOf(pending.solution, pending.project)
                });
        }
    });

    readonly confirmHeader = computed(() => {
        this.i18n.translations();
        switch (this.pending()?.kind) {
            case 'delete-solution':
                return this.i18n.t('solutions.header_delete_solution');
            case 'delete-project':
                return this.i18n.t('solutions.header_delete_project');
            case 'unfile':
                return this.i18n.t('solutions.header_unfile');
            default:
                return '';
        }
    });

    // --- Filing ---------------------------------------------------------------------------------

    readonly filing = signal<Filing | null>(null);
    readonly fileVisible = signal(false);
    readonly targetProjectId = signal<number | null>(null);

    /** Every project the repository or image could move to, grouped by solution; the one it is in is left out. */
    readonly projectChoices = computed(() => {
        const current = this.filing()?.from?.project.id ?? null;
        return this.solutions()
            .map((solution) => ({
                label: solution.name,
                items: (solution.projects ?? [])
                    .filter((project) => project.id !== current)
                    .map((project) => ({ label: project.name, value: project.id }))
            }))
            .filter((group) => group.items.length > 0);
    });

    /**
     * Who gains and who loses sight of the repository or image. Said before the click: a move reads as
     * housekeeping and is, in fact, a change of access for everybody holding either project.
     */
    readonly filingConsequence = computed(() => {
        this.i18n.translations();
        const filing = this.filing();
        const target = this.projectPath(this.targetProjectId());
        if (!filing || !target) return null;
        return filing.from
            ? this.i18n.t('solutions.move_consequence', {
                  target: filing.target.ref.name,
                  from: pathOf(filing.from.solution, filing.from.project),
                  to: target
              })
            : this.i18n.t('solutions.file_consequence', { target: filing.target.ref.name, to: target });
    });

    // --- Moving a project ---------------------------------------------------------------------------

    readonly moving = signal<{ solution: SolutionNode; project: ProjectNode } | null>(null);
    readonly moveVisible = signal(false);
    readonly targetSolutionId = signal<number | null>(null);
    readonly moveName = signal('');
    readonly moveNameTaken = signal<string | null>(null);

    /**
     * The other solutions only. Offering the current one would offer a click that changes nothing
     * and still reads, after the notice, as if something had moved.
     */
    readonly solutionChoices = computed(() => {
        const current = this.moving()?.solution.id ?? null;
        return this.solutions()
            .filter((solution) => solution.id !== current)
            .map((solution) => ({ label: solution.name, value: solution.id }));
    });

    // --- Plugins switched on for a project (decision 0017) -----------------------------------------

    readonly pluginsProject = signal<{ solution: SolutionNode; project: ProjectNode } | null>(null);
    readonly pluginsVisible = signal(false);
    readonly registry = signal<Plugin[] | null>(null);
    readonly activations = signal<Map<string, PluginActivation>>(new Map());
    readonly pluginsError = signal<string | null>(null);
    readonly pluginBusy = signal<string | null>(null);
    private readonly pluginsLoad = new LatestRequest();

    /**
     * The project's visible repositories whose languages nobody has counted yet. Named, because
     * "two repositories" sends the reader looking; the names are in the tree already.
     */
    readonly unknownLanguages = computed(() => {
        const project = this.pluginsProject()?.project;
        const ids = new Set(project ? unknownFor(project) : []);
        const names = (project?.repositories ?? []).filter((r) => ids.has(r.id)).map((r) => r.name);
        return { count: ids.size, names: names.join(', ') };
    });

    /**
     * The union the dialog shows — `null` when nothing was counted and something is unknown, so a
     * project whose only repository is unscanned reads "not yet known", not "no language".
     */
    readonly projectLanguages = computed<readonly string[] | null>(() => {
        const project = this.pluginsProject()?.project;
        if (!project) return null;
        const languages = languagesOf(project);
        return languages.length === 0 && unknownFor(project).length > 0 ? null : languages;
    });

    /**
     * Each plugin's languages against the project's (information, never a block: the count can be
     * stale by one push). Disjoint with every repository counted means `not_applicable` at the next
     * scan; disjoint with some uncounted only says "so far", since those may hold one of them.
     */
    readonly pluginFits = computed(() => {
        const fits = new Map<string, PluginFit>();
        const project = this.pluginsProject()?.project;
        if (!project) return fits;
        const present = new Set<string>(languagesOf(project));
        const someUnknown = unknownFor(project).length > 0;
        for (const plugin of this.registry() ?? []) {
            const matched = plugin.manifest.languages.filter((language) => present.has(language));
            fits.set(plugin.id, {
                matched: new Set(matched),
                verdict: matched.length > 0 ? 'present' : someUnknown ? 'absent_so_far' : 'absent',
                list: matched.join(', ')
            });
        }
        return fits;
    });

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

    /** On with a `PUT`, off with a `DELETE`; the row follows what the server answered, not the click. */
    togglePlugin(plugin: Plugin, on: boolean): void {
        const target = this.pluginsProject();
        if (!target) return;
        const projectId = target.project.id;
        this.pluginBusy.set(plugin.id);
        this.pluginsError.set(null);
        const done = (next: Map<string, PluginActivation>) => {
            this.pluginBusy.set(null);
            this.activations.set(next);
        };
        const fail = (failure: unknown) => {
            this.pluginBusy.set(null);
            // Re-set so the switch returns to the stored state: the model was bound to the click.
            this.activations.set(new Map(this.activations()));
            this.pluginsError.set(messageOf(failure, this.i18n.t('solutions.plugins_error_change')));
        };
        if (on) {
            this.pluginsApi.activatePlugin(projectId, plugin.id).subscribe({
                next: (activation) => done(new Map(this.activations()).set(plugin.id, activation)),
                error: fail
            });
        } else {
            this.pluginsApi.deactivatePlugin(projectId, plugin.id).subscribe({
                next: () => {
                    const next = new Map(this.activations());
                    next.delete(plugin.id);
                    done(next);
                },
                error: fail
            });
        }
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

    total(issues: OpenIssues | null | undefined): number {
        return issues?.total ?? 0;
    }

    count(issues: OpenIssues | null | undefined, field: Severity): number {
        return issues?.[field] ?? 0;
    }

    /**
     * The list a badge counts. `unsettled` is not optional: the tree's figures leave settled triage
     * out, and without it "3 high" opens a list of five — the list is right about something else,
     * and the figure is what looks wrong.
     */
    issuesLink(
        scope: { project_id: number } | { solution_id: number },
        severity: Severity
    ): Record<string, string | number | boolean> {
        return { ...scope, severity, unsettled: true };
    }

    /** "Open the issues of high severity in FinBackoffice / Develop (5)" — the tag alone says "5 High". */
    openIssuesLabel(count: number, severity: string, name: string): string {
        return this.i18n.t('solutions.aria_open_issues', {
            count,
            severity: severity.toLocaleLowerCase(this.i18n.currentLang()),
            name
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

    saveEditor(): void {
        const editing = this.editing();
        if (!editing) return;
        const name = this.formName().trim();
        if (!name) {
            this.formError.set(this.i18n.t('solutions.name_required'));
            return;
        }
        // Sent as typed, empty included: on a change the server reads an empty description as
        // "clear it", which is what emptying the field means.
        const body = { name, description: this.formDescription().trim() };

        const request: Observable<unknown> =
            editing.kind === 'solution'
                ? editing.solution
                    ? this.api.updateSolution(editing.solution.id, body)
                    : this.api.createSolution(body)
                : editing.project
                  ? this.api.updateProject(editing.project.id, body)
                  : this.api.createProject(editing.solution.id, body);

        this.saving.set(true);
        this.formError.set(null);
        request.subscribe({
            next: () => {
                this.saving.set(false);
                this.editorVisible.set(false);
                this.reload();
            },
            error: (failure) => {
                this.saving.set(false);
                // Kept in the dialog: a name already taken is the usual refusal, and closing the
                // dialog to say so would lose what was typed.
                this.formError.set(
                    this.nameTaken(failure, editing, name) ?? messageOf(failure, this.i18n.t('solutions.error_save'))
                );
            }
        });
    }

    /**
     * A taken name, read from the 409's type and said in the screen's language — null for any other
     * refusal. The server answers a taken name the same way whether the dialog creates or renames (it
     * used to be a 400 on those and a 409 on a move), so the type is what tells it apart, never the
     * status or the English sentence.
     */
    private nameTaken(failure: unknown, editing: Editing, name: string): string | null {
        const type = problemType(failure);
        if (editing.kind === 'solution' && type === SOLUTION_NAME_TAKEN) {
            return this.i18n.t('solutions.solution_name_taken', { name });
        }
        if (editing.kind === 'project' && type === PROJECT_NAME_TAKEN) {
            return this.i18n.t('solutions.project_name_taken', { solution: editing.solution.name, name });
        }
        return null;
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

    confirm(): void {
        const pending = this.pending();
        if (!pending) return;
        const request =
            pending.kind === 'delete-solution'
                ? this.api.deleteSolution(pending.solution.id)
                : pending.kind === 'delete-project'
                  ? this.api.deleteProject(pending.project.id)
                  : pending.target.kind === 'container'
                    ? this.api.unfileContainer(pending.project.id, pending.target.ref.id)
                    : this.api.unfileRepository(pending.project.id, pending.target.ref.id);

        this.saving.set(true);
        request.subscribe({
            next: () => {
                this.saving.set(false);
                this.confirmVisible.set(false);
                this.reload();
            },
            error: (failure) => {
                this.saving.set(false);
                this.confirmVisible.set(false);
                // The 409 on a solution that still holds projects carries the server's sentence,
                // which says what to do; a generic "could not delete" would not.
                this.error.set(messageOf(failure, this.i18n.t('solutions.error_change')));
                this.reload(true);
            }
        });
    }

    // --- File, move -----------------------------------------------------------------------------

    openFile(target: Filed, from: { solution: SolutionNode; project: ProjectNode } | null = null): void {
        this.filing.set({ target, from });
        this.targetProjectId.set(null);
        this.formError.set(null);
        this.fileVisible.set(true);
    }

    saveFile(): void {
        const filing = this.filing();
        const projectId = this.targetProjectId();
        if (!filing || projectId === null) return;

        this.saving.set(true);
        this.formError.set(null);
        const { target } = filing;
        const request =
            target.kind === 'container'
                ? this.api.fileContainer(projectId, target.ref.id)
                : this.api.fileRepository(projectId, target.ref.id);
        request.subscribe({
            next: () => {
                this.saving.set(false);
                this.fileVisible.set(false);
                this.reload();
            },
            error: (failure) => {
                this.saving.set(false);
                this.formError.set(messageOf(failure, this.i18n.t('solutions.error_change')));
            }
        });
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

    /**
     * Only `solutionId`, and `name` when one was typed: a missing field is "unchanged" to the server,
     * so a move never rewrites a description it was not asked about.
     */
    saveMoveProject(): void {
        const moving = this.moving();
        const solutionId = this.targetSolutionId();
        if (!moving || solutionId === null) return;
        const target = this.solutions().find((solution) => solution.id === solutionId);
        if (!target) return;
        const name = this.moveName().trim();
        const body: Schema<'ProjectChange'> = name ? { solutionId, name } : { solutionId };

        this.saving.set(true);
        this.formError.set(null);
        this.moveNameTaken.set(null);
        this.api.updateProject(moving.project.id, body).subscribe({
            next: (moved) => {
                this.saving.set(false);
                this.moveVisible.set(false);
                this.notice.set(this.i18n.t('solutions.project_moved', { project: moved.name, solution: target.name }));
                this.reload();
            },
            error: (failure) => {
                this.saving.set(false);
                // The dialog stays open with the name field beside the sentence: renaming is the way
                // out of this refusal, and closing would make the administrator start again.
                if (problemType(failure) === PROJECT_NAME_TAKEN) {
                    this.moveNameTaken.set(
                        this.i18n.t('solutions.move_project_name_taken', {
                            solution: target.name,
                            name: name || moving.project.name
                        })
                    );
                    return;
                }
                this.formError.set(messageOf(failure, this.i18n.t('solutions.error_change')));
            }
        });
    }

    private projectPath(projectId: number | null): string | null {
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

const PROJECT_NAME_TAKEN = 'urn:vectispire:problem:project-name-taken';
const SOLUTION_NAME_TAKEN = 'urn:vectispire:problem:solution-name-taken';

/** The RFC 7807 `type` of a refusal, so a refusal the screen can answer is told from one it can only show. */
function problemType(failure: unknown): unknown {
    return (failure as { error?: { type?: unknown } } | null)?.error?.type;
}

/** "Solution / Project" — how the server names a project in a grant, and so how this screen does. */
function pathOf(solution: SolutionNode, project: ProjectNode): string {
    return `${solution.name} / ${project.name}`;
}
