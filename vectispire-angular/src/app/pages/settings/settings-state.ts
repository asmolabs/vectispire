import { DestroyRef, Injectable, computed, inject, signal } from '@angular/core';
import { messageOf } from '../../core/api-error';
import { SettingsApi } from '../../core/api/settings.api';
import type { SettingDefinition } from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';

export type SettingsTab = 'general' | 'scanners' | 'ai' | 'integrations' | 'threat-intel' | 'governance';

/**
 * What the settings screen's sections share, and nothing they do not.
 *
 * <p>Provided by {@link Settings} itself rather than in root: it lives and dies with the page, so
 * leaving the screen discards unsaved values exactly as it did when all of this was one component.
 *
 * <p>Shared because more than one section reads or writes it: the catalogue and its values (the
 * generic form, the model review block and the risk dialog all read them; the save button sits in
 * the page header), and the error and success banners, which every section's own save reports to.
 */
@Injectable()
export class SettingsState {
    private readonly settingsApi = inject(SettingsApi);
    private readonly i18n = inject(I18nService);

    readonly catalog = signal<SettingDefinition[]>([]);
    readonly values = signal<Record<string, string>>({});
    readonly error = signal<string | null>(null);
    readonly saving = signal(false);
    readonly saved = signal(false);

    /** What changed since loading. Drives the button, and sends only the delta. */
    private original: Record<string, string> = {};

    readonly dirty = computed(() => Object.entries(this.values()).some(([key, value]) => this.original[key] !== value));

    readonly sections = computed(() => {
        const groups = new Map<string, SettingDefinition[]>();
        for (const setting of this.catalog()) {
            const existing = groups.get(setting.section) ?? [];
            existing.push(setting);
            groups.set(setting.section, existing);
        }
        return [...groups].map(([name, settings]) => ({ name, settings }));
    });

    /** Which provider is selected right now, read from the settings the form holds. */
    readonly aiProvider = computed(() => this.values()['ai_review_provider'] ?? 'ollama');

    /** The URL in use, named in the warning so it points at something the operator can check. */
    readonly aiEndpoint = computed(() =>
        this.aiProvider() === 'openai'
            ? this.values()['ai_review_openai_url'] || 'https://api.openai.com/v1'
            : this.values()['ai_review_ollama_url'] || 'http://localhost:11434'
    );

    private readonly loaders = new Set<() => void>();

    /**
     * Runs a section's loader now, and again after every save of the generic form.
     *
     * <p>Kept from the single component, where one `reload()` re-read every card after a save:
     * splitting the screen must not quietly change which state a save refreshes. The loader is
     * dropped with the section that registered it, so a section recreated on a tab switch does not
     * leave a dead one behind.
     */
    register(loader: () => void, destroyRef: DestroyRef): void {
        this.loaders.add(loader);
        destroyRef.onDestroy(() => this.loaders.delete(loader));
        loader();
    }

    set(key: string, value: string): void {
        this.values.update((current) => ({ ...current, [key]: value }));
        this.saved.set(false);
    }

    save(): void {
        // Only what changed: sending the whole catalogue would write rows for settings nobody
        // ever touched, and the screen could no longer say which ones stayed at their
        // default.
        const changed = Object.fromEntries(
            Object.entries(this.values()).filter(([key, value]) => this.original[key] !== value)
        );
        if (Object.keys(changed).length === 0) return;

        this.saving.set(true);
        this.error.set(null);
        this.settingsApi.updateSettings(changed).subscribe({
            next: () => {
                this.saving.set(false);
                this.saved.set(true);
                this.reload();
            },
            error: (response) => {
                this.saving.set(false);
                // The server's message carries the offending setting's label and the expected
                // value; replacing it with generic text would lose that.
                this.error.set(messageOf(response, this.i18n.t('settings.error_save')));
            }
        });
    }

    reload(): void {
        for (const loader of this.loaders) loader();

        this.settingsApi.settings().subscribe({
            next: ({ settings }) => {
                this.catalog.set(settings);
                const values = Object.fromEntries(settings.map((setting) => [setting.key, setting.value]));
                this.values.set(values);
                this.original = { ...values };
            },
            error: () => this.error.set(this.i18n.t('settings.error_load'))
        });
    }
}
