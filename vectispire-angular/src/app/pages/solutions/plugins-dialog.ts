import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, computed, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { MessageModule } from '@openng/optimus-ui/message';
import { TagModule } from '@openng/optimus-ui/tag';
import { ToggleSwitchModule } from '@openng/optimus-ui/toggleswitch';
import { messageOf } from '../../core/api-error';
import { PluginsApi } from '../../core/api/plugins.api';
import type { Plugin, PluginActivation } from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { DetectedLanguages } from '../../shared/detected-languages';
import { languagesOf, PluginFit, SolutionsPage, unknownFor } from './solutions-page';

/**
 * The plugins a project runs (decision 0017): the registry beside the project's activations, each
 * plugin with the languages it would look for against the project's. Read by governance, switched by
 * a security lead; a plugin disabled on the platform keeps its activation and runs nowhere, and the
 * dialog says so rather than let a switch that is on read as "running".
 */
@Component({
    selector: 'app-plugins-dialog',
    imports: [
        DatePipe,
        FormsModule,
        ButtonModule,
        DialogModule,
        MessageModule,
        TagModule,
        ToggleSwitchModule,
        TranslatePipe,
        DetectedLanguages
    ],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './plugins-dialog.html'
})
export class PluginsDialog {
    private readonly pluginsApi = inject(PluginsApi);
    private readonly i18n = inject(I18nService);
    protected readonly page = inject(SolutionsPage);

    /**
     * The project's visible repositories whose languages nobody has counted yet. Named, because
     * "two repositories" sends the reader looking; the names are in the tree already.
     */
    readonly unknownLanguages = computed(() => {
        const project = this.page.pluginsProject()?.project;
        const ids = new Set(project ? unknownFor(project) : []);
        const names = (project?.repositories ?? []).filter((r) => ids.has(r.id)).map((r) => r.name);
        return { count: ids.size, names: names.join(', ') };
    });

    /**
     * The union the dialog shows — `null` when nothing was counted and something is unknown, so a
     * project whose only repository is unscanned reads "not yet known", not "no language".
     */
    readonly projectLanguages = computed<readonly string[] | null>(() => {
        const project = this.page.pluginsProject()?.project;
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
        const project = this.page.pluginsProject()?.project;
        if (!project) return fits;
        const present = new Set<string>(languagesOf(project));
        const someUnknown = unknownFor(project).length > 0;
        for (const plugin of this.page.registry() ?? []) {
            const matched = plugin.manifest.languages.filter((language) => present.has(language));
            fits.set(plugin.id, {
                matched: new Set(matched),
                verdict: matched.length > 0 ? 'present' : someUnknown ? 'absent_so_far' : 'absent',
                list: matched.join(', ')
            });
        }
        return fits;
    });

    /** Each plugin with its fit and its activation, worked out when either changes — not per pass. */
    protected readonly rows = computed(() => {
        const registry = this.page.registry();
        if (registry === null) return null;
        const fits = this.pluginFits();
        const activations = this.page.activations();
        return registry.map((plugin) => ({
            ...plugin,
            plugin,
            fit: fits.get(plugin.id) ?? null,
            activation: activations.get(plugin.id) ?? null
        }));
    });

    /** On with a `PUT`, off with a `DELETE`; the row follows what the server answered, not the click. */
    togglePlugin(plugin: Plugin, on: boolean): void {
        const target = this.page.pluginsProject();
        if (!target) return;
        const projectId = target.project.id;
        this.page.pluginBusy.set(plugin.id);
        this.page.pluginsError.set(null);
        const done = (next: Map<string, PluginActivation>) => {
            this.page.pluginBusy.set(null);
            this.page.activations.set(next);
        };
        const fail = (failure: unknown) => {
            this.page.pluginBusy.set(null);
            // Re-set so the switch returns to the stored state: the model was bound to the click.
            this.page.activations.set(new Map(this.page.activations()));
            this.page.pluginsError.set(messageOf(failure, this.i18n.t('solutions.plugins_error_change')));
        };
        if (on) {
            this.pluginsApi.activatePlugin(projectId, plugin.id).subscribe({
                next: (activation) => done(new Map(this.page.activations()).set(plugin.id, activation)),
                error: fail
            });
        } else {
            this.pluginsApi.deactivatePlugin(projectId, plugin.id).subscribe({
                next: () => {
                    const next = new Map(this.page.activations());
                    next.delete(plugin.id);
                    done(next);
                },
                error: fail
            });
        }
    }
}
