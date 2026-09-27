import { CommonModule } from '@angular/common';
import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputNumberModule } from '@openng/optimus-ui/inputnumber';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { MultiSelectModule } from '@openng/optimus-ui/multiselect';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { TextareaModule } from '@openng/optimus-ui/textarea';
import { ToggleSwitchModule } from '@openng/optimus-ui/toggleswitch';
import { messageOf } from '../../core/api-error';
import { PluginsApi } from '../../core/api/plugins.api';
import { SolutionsApi } from '../../core/api/solutions.api';
import type { Plugin, PluginActivation, PluginLanguage, PluginManifest, SolutionTree } from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { LatestRequest } from '../../core/latest-request';
import { SessionStore } from '../../core/session.store';

/**
 * The languages a manifest may declare, in the catalogue's order.
 *
 * Written out because a select needs values at runtime and the document's union exists only at
 * compile time. The assertion below keeps the two in step: a language the server adds and this list
 * lacks stops the build, rather than leaving the form unable to offer it.
 */
export const PLUGIN_LANGUAGES = [
    'apex',
    'bash',
    'c',
    'clojure',
    'csharp',
    'dockerfile',
    'elixir',
    'go',
    'html',
    'java',
    'javascript',
    'json',
    'kotlin',
    'ocaml',
    'php',
    'python',
    'ruby',
    'rust',
    'scala',
    'solidity',
    'swift',
    'terraform',
    'typescript',
    'yaml'
] as const satisfies readonly PluginLanguage[];
type Unlisted = Exclude<PluginLanguage, (typeof PLUGIN_LANGUAGES)[number]>;
const EVERY_LANGUAGE_LISTED: Unlisted extends never ? true : Unlisted = true;
void EVERY_LANGUAGE_LISTED;

/** The form's own shape: exit codes are typed as text and read on save, so a half-typed list is never a manifest. */
interface Draft {
    id: string;
    name: string;
    image: string;
    languages: PluginLanguage[];
    arguments: string[];
    output: string;
    exitCodes: string;
    network: boolean;
    networkJustification: string;
    timeoutSeconds: number | null;
}

/** The server's bounds (decision 0017 §2), repeated only to shape the inputs; it stays the judge. */
export const JUSTIFICATION_MIN = 20;
export const JUSTIFICATION_MAX = 500;

/**
 * The plugin registry (decision 0017).
 *
 * **Every account reads it**: an image, arguments and languages name no target, and a developer
 * whose scan lists a plugin as absent needs to see what that plugin is. Registering, updating and
 * enabling are the platform governor's — third-party code that will read the source of every
 * project it is switched on for — and which projects a plugin reads is answered to the governance
 * roles only. The screen offers each action to the role the server accepts it from, and shows the
 * server's refusal as it comes.
 *
 * **There is no delete, and the id can never change.** The id is in every issue fingerprint the
 * plugin opened; other code registered under it would inherit their triage. The form says so where
 * the id is typed, which is the only moment the warning can still change anything.
 */
@Component({
    selector: 'app-plugins',
    standalone: true,
    imports: [
        CommonModule,
        FormsModule,
        ButtonModule,
        CardModule,
        DialogModule,
        InputNumberModule,
        InputTextModule,
        MessageModule,
        MultiSelectModule,
        TableModule,
        TagModule,
        TextareaModule,
        ToggleSwitchModule,
        TranslatePipe
    ],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './plugins.html'
})
export class Plugins {
    private readonly api = inject(PluginsApi);
    private readonly solutionsApi = inject(SolutionsApi);
    private readonly i18n = inject(I18nService);
    private readonly session = inject(SessionStore);
    private readonly router = inject(Router);
    private readonly route = inject(ActivatedRoute);
    private readonly detailRequest = new LatestRequest();

    readonly governs = this.session.governsPlatform;
    readonly readsGovernance = this.session.canReadGovernance;
    readonly justificationMin = JUSTIFICATION_MIN;
    readonly justificationMax = JUSTIFICATION_MAX;
    readonly languageOptions = PLUGIN_LANGUAGES.map((language) => ({ label: language, value: language }));

    readonly plugins = signal<Plugin[]>([]);
    readonly loading = signal(true);
    readonly error = signal<string | null>(null);
    readonly notice = signal<string | null>(null);
    readonly busy = signal<string | null>(null);

    /** The plugin opened below the list — from a row, or from a link carrying `?id=`. */
    readonly selected = signal<Plugin | null>(null);
    readonly selectedError = signal<string | null>(null);
    readonly projects = signal<PluginActivation[] | null>(null);
    private readonly tree = signal<SolutionTree | null>(null);

    /** "Solution / Project", as grants name a project; the bare id when the tree does not hold it. */
    readonly projectNames = computed(() => {
        const names = new Map<number, string>();
        for (const solution of this.tree()?.solutions ?? []) {
            for (const project of solution.projects ?? []) {
                names.set(project.id, `${solution.name} / ${project.name}`);
            }
        }
        return names;
    });

    readonly formVisible = signal(false);
    readonly editing = signal<Plugin | null>(null);
    readonly saving = signal(false);
    readonly formError = signal<string | null>(null);
    draft: Draft = blank();

    constructor() {
        this.reload();
        const id = this.route.snapshot.queryParamMap.get('id');
        if (id) this.open(id);
    }

    reload(): void {
        this.loading.set(true);
        this.api.plugins().subscribe({
            next: (plugins) => {
                this.plugins.set(plugins);
                this.loading.set(false);
            },
            error: (failure) => {
                this.error.set(messageOf(failure, this.i18n.t('plugins.error_load')));
                this.loading.set(false);
            }
        });
    }

    /**
     * Opens one plugin, and the projects it reads for a governance reader. The URL follows, so the
     * link a scan's outcome carries and the one a reader copies from here are the same link.
     */
    open(id: string): void {
        this.selectedError.set(null);
        this.projects.set(null);
        void this.router.navigate([], { relativeTo: this.route, queryParams: { id }, replaceUrl: true });
        this.detailRequest.run(this.api.plugin(id), {
            next: (plugin) => {
                this.selected.set(plugin);
                if (this.readsGovernance()) this.loadProjects(plugin.id);
            },
            error: (failure) => {
                this.selected.set(null);
                // A 404 is an id nobody registered — or a link typed by hand. Said as such, not as a
                // failure to load: there is nothing to retry.
                this.selectedError.set(
                    (failure as { status?: number } | null)?.status === 404
                        ? this.i18n.t('plugins.error_not_found', { id })
                        : messageOf(failure, this.i18n.t('plugins.error_load_one'))
                );
            }
        });
    }

    close(): void {
        this.selected.set(null);
        this.selectedError.set(null);
        void this.router.navigate([], { relativeTo: this.route, queryParams: {}, replaceUrl: true });
    }

    private loadProjects(id: string): void {
        this.api.pluginProjects(id).subscribe({
            next: (activations) => this.projects.set(activations),
            error: () => this.projects.set([])
        });
        if (!this.tree()) {
            // For the names only: a failure leaves the ids, which are still the right answer.
            this.solutionsApi.solutionTree().subscribe({ next: (tree) => this.tree.set(tree), error: () => undefined });
        }
    }

    projectName(projectId: number): string {
        return this.projectNames().get(projectId) ?? `#${projectId}`;
    }

    shortDigest(digest: string | null | undefined): string {
        return digest ? digest.slice(0, 12) : '—';
    }

    // --- Register, edit --------------------------------------------------------------------------

    openRegister(): void {
        this.editing.set(null);
        this.draft = blank();
        this.formError.set(null);
        this.formVisible.set(true);
    }

    openEdit(plugin: Plugin): void {
        this.editing.set(plugin);
        this.draft = draftOf(plugin.manifest);
        this.formError.set(null);
        this.formVisible.set(true);
    }

    addArgument(): void {
        this.draft.arguments = [...this.draft.arguments, ''];
    }

    removeArgument(index: number): void {
        this.draft.arguments = this.draft.arguments.filter((_, at) => at !== index);
    }

    /** `trackBy` for the argument inputs: by position, so typing does not re-create the field. */
    trackIndex(index: number): number {
        return index;
    }

    save(): void {
        const exitCodes = parseExitCodes(this.draft.exitCodes);
        if (exitCodes === null) {
            this.formError.set(this.i18n.t('plugins.error_exit_codes'));
            return;
        }
        const manifest = manifestOf(this.draft, exitCodes);
        const editing = this.editing();
        const request = editing ? this.api.updatePlugin(editing.id, manifest) : this.api.registerPlugin(manifest);

        this.saving.set(true);
        this.formError.set(null);
        request.subscribe({
            next: (plugin) => {
                this.saving.set(false);
                this.formVisible.set(false);
                this.notice.set(
                    this.i18n.t(editing ? 'plugins.updated_notice' : 'plugins.registered_notice', {
                        id: plugin.id,
                        digest: this.shortDigest(plugin.manifestDigest)
                    })
                );
                this.reload();
                if (this.selected()?.id === plugin.id || !editing) this.open(plugin.id);
            },
            error: (failure) => {
                this.saving.set(false);
                // Kept in the dialog with the server's sentence: a taken id (409), a tag beside the
                // digest, a justification too short — each says which field to fix.
                this.formError.set(messageOf(failure, this.i18n.t('plugins.error_save')));
            }
        });
    }

    /** Off everywhere from the next scan; its activations are kept, so switching back restores them. */
    setEnabled(plugin: Plugin, enabled: boolean): void {
        this.busy.set(plugin.id);
        this.error.set(null);
        this.api.setPluginEnabled(plugin.id, enabled).subscribe({
            next: (updated) => {
                this.busy.set(null);
                this.plugins.update((plugins) => plugins.map((one) => (one.id === updated.id ? updated : one)));
                if (this.selected()?.id === updated.id) this.selected.set(updated);
                this.notice.set(
                    this.i18n.t(enabled ? 'plugins.enabled_notice' : 'plugins.disabled_notice', { id: updated.id })
                );
            },
            error: (failure) => {
                this.busy.set(null);
                this.error.set(messageOf(failure, this.i18n.t('plugins.error_enable')));
            }
        });
    }
}

function blank(): Draft {
    return {
        id: '',
        name: '',
        image: '',
        languages: [],
        arguments: ['{source}'],
        output: 'results.sarif',
        exitCodes: '0',
        network: false,
        networkJustification: '',
        timeoutSeconds: null
    };
}

function draftOf(manifest: PluginManifest): Draft {
    return {
        id: manifest.id,
        name: manifest.name,
        image: manifest.image,
        languages: [...manifest.languages],
        arguments: [...manifest.arguments],
        output: manifest.output ?? '',
        exitCodes: manifest.exit_codes.join(', '),
        network: manifest.network,
        networkJustification: manifest.network_justification ?? '',
        timeoutSeconds: manifest.timeout_seconds
    };
}

/** "0, 1" → [0, 1]; null for anything that is not a list of integers. Blank means the default, `[0]`. */
export function parseExitCodes(text: string): number[] | null {
    const parts = text
        .split(/[\s,]+/)
        .map((part) => part.trim())
        .filter((part) => part.length > 0);
    if (parts.length === 0) return [0];
    if (parts.some((part) => !/^-?\d+$/.test(part))) return null;
    return [...new Set(parts.map(Number))];
}

/**
 * The manifest the server receives. **Every field, always** — the digest covers them all, and a
 * field left for the server to default would still be a field the governor did not see. The one
 * exception is deliberate: a justification is sent only with the network on, because the server
 * refuses one without it rather than store a reason for an exception that does not exist.
 */
export function manifestOf(draft: Draft, exitCodes: number[]): PluginManifest {
    return {
        id: draft.id.trim(),
        name: draft.name.trim(),
        image: draft.image.trim(),
        languages: draft.languages,
        arguments: draft.arguments,
        output: draft.output.trim() || null,
        exit_codes: exitCodes,
        network: draft.network,
        network_justification: draft.network ? draft.networkJustification.trim() || null : null,
        timeout_seconds: draft.timeoutSeconds
    };
}
