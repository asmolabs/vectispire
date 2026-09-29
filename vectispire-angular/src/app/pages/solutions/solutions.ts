import { CommonModule } from '@angular/common';
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
    OpenIssues,
    Plugin,
    PluginActivation,
    ProjectNode,
    RepositoryRef,
    SolutionNode,
    SolutionTree
} from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { LatestRequest } from '../../core/latest-request';
import { SessionStore } from '../../core/session.store';

/** The server's limits (decision 0023), enforced in the form so a long name is stopped as it is typed. */
export const NAME_MAX = 100;
export const DESCRIPTION_MAX = 255;

type Severity = Exclude<keyof OpenIssues, 'total'>;

/** What the name-and-description dialog is editing. */
type Editing =
    | { kind: 'solution'; solution: SolutionNode | null }
    | { kind: 'project'; solution: SolutionNode; project: ProjectNode | null };

/** The three changes that take something away from somebody, and so are confirmed first. */
type Pending =
    | { kind: 'delete-solution'; solution: SolutionNode }
    | { kind: 'delete-project'; solution: SolutionNode; project: ProjectNode }
    | { kind: 'unfile'; repository: RepositoryRef; solution: SolutionNode; project: ProjectNode };

/** The repository being filed, and the project it is in today, if any. */
interface Filing {
    repository: RepositoryRef;
    from: { solution: SolutionNode; project: ProjectNode } | null;
}

/**
 * Solutions → projects → repositories (decision 0023).
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
    standalone: true,
    imports: [
        CommonModule,
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
        TranslatePipe
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
    readonly nameMax = NAME_MAX;
    readonly descriptionMax = DESCRIPTION_MAX;

    readonly tree = signal<SolutionTree | null>(null);
    readonly loading = signal(true);
    readonly saving = signal(false);
    readonly error = signal<string | null>(null);
    readonly formError = signal<string | null>(null);

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
                    count: pending.project.repositoryCount
                });
            case 'unfile':
                return this.i18n.t('solutions.unfile_consequence', {
                    repository: pending.repository.name,
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

    /** Every project the repository could move to, grouped by solution; the one it is in is left out. */
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
     * Who gains and who loses sight of the repository. Said before the click: a move reads as
     * housekeeping and is, in fact, a change of access for everybody holding either project.
     */
    readonly filingConsequence = computed(() => {
        this.i18n.translations();
        const filing = this.filing();
        const target = this.projectPath(this.targetProjectId());
        if (!filing || !target) return null;
        return filing.from
            ? this.i18n.t('solutions.move_consequence', {
                  repository: filing.repository.name,
                  from: pathOf(filing.from.solution, filing.from.project),
                  to: target
              })
            : this.i18n.t('solutions.file_consequence', { repository: filing.repository.name, to: target });
    });

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
                this.formError.set(messageOf(failure, this.i18n.t('solutions.error_save')));
            }
        });
    }

    // --- Delete, remove -------------------------------------------------------------------------

    askDeleteSolution(solution: SolutionNode): void {
        this.ask({ kind: 'delete-solution', solution });
    }

    askDeleteProject(solution: SolutionNode, project: ProjectNode): void {
        this.ask({ kind: 'delete-project', solution, project });
    }

    askUnfile(repository: RepositoryRef, solution: SolutionNode, project: ProjectNode): void {
        this.ask({ kind: 'unfile', repository, solution, project });
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
                  : this.api.unfileRepository(pending.project.id, pending.repository.id);

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

    openFile(repository: RepositoryRef, from: { solution: SolutionNode; project: ProjectNode } | null = null): void {
        this.filing.set({ repository, from });
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
        this.api.fileRepository(projectId, filing.repository.id).subscribe({
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

/** "Solution / Project" — how the server names a project in a grant, and so how this screen does. */
function pathOf(solution: SolutionNode, project: ProjectNode): string {
    return `${solution.name} / ${project.name}`;
}
