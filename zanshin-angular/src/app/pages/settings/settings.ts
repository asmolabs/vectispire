import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { InputNumberModule } from '@openng/optimus-ui/inputnumber';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { ToggleSwitchModule } from '@openng/optimus-ui/toggleswitch';
import { messageOf } from '../../core/api-error';
import { ApiService } from '../../core/api.service';
import type { OllamaCheck, SettingDefinition } from '../../core/api.models';

const SEVERITIES = [
    { label: 'Critical', value: 'critical' },
    { label: 'High', value: 'high' },
    { label: 'Medium', value: 'medium' },
    { label: 'Low', value: 'low' }
];

@Component({
    selector: 'app-settings',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, CardModule, InputNumberModule, InputTextModule, MessageModule, SelectModule, ToggleSwitchModule],
    templateUrl: './settings.html'
})
export class Settings {
    private readonly api = inject(ApiService);
    readonly severities = SEVERITIES;

    readonly catalog = signal<SettingDefinition[]>([]);
    readonly values = signal<Record<string, string>>({});
    readonly error = signal<string | null>(null);
    readonly saving = signal(false);
    readonly saved = signal(false);

    readonly tokenConfigured = signal(false);
    readonly savingToken = signal(false);
    tokenInput = '';

    /** What changed since loading. Drives the button, and sends only the delta. */
    private original: Record<string, string> = {};

    readonly dirty = computed(() => Object.entries(this.values()).some(([key, value]) => this.original[key] !== value));

    /**
     * Matched on the settings it holds, not on its title.
     *
     * <p>The server sends a human label — it used to send the raw enum name, which is why this
     * screen said `model_review`. A label is prose and prose gets reworded; keying the button to
     * it would make the button vanish silently the day somebody improves the wording. The keys
     * are the contract.
     */
    isModelReview(section: { settings: SettingDefinition[] }): boolean {
        return section.settings.some((setting) => setting.key.startsWith('ai_review_'));
    }

    readonly ollama = signal<OllamaCheck | null>(null);
    readonly testingOllama = signal(false);

    testOllama(): void {
        this.testingOllama.set(true);
        this.ollama.set(null);
        this.api.testOllama().subscribe({
            next: (check) => {
                this.ollama.set(check);
                this.testingOllama.set(false);
            },
            error: () => {
                this.testingOllama.set(false);
                // Reported as an answer rather than an error banner: "the check itself failed" is
                // still information about the configuration being tested.
                this.ollama.set({
                    reachable: false,
                    modelInstalled: false,
                    model: '',
                    url: '',
                    models: [],
                    detail: 'The connection test could not be run.'
                });
            }
        });
    }

    readonly sections = computed(() => {
        const groups = new Map<string, SettingDefinition[]>();
        for (const setting of this.catalog()) {
            const existing = groups.get(setting.section) ?? [];
            existing.push(setting);
            groups.set(setting.section, existing);
        }
        return [...groups].map(([name, settings]) => ({ name, settings }));
    });

    constructor() {
        this.reload();
    }

    set(key: string, value: string): void {
        this.values.update((current) => ({ ...current, [key]: value }));
        this.saved.set(false);
    }

    asNumber(value: string): number {
        const parsed = Number(value);
        return Number.isFinite(parsed) ? parsed : 0;
    }

    /** `p-inputnumber` yields `null` when the field is cleared; the server refuses empty. */
    numberToText(value: number | null): string {
        return value === null || value === undefined ? '0' : String(value);
    }

    save(): void {
        // Only what changed: sending the whole catalogue would write rows for settings nobody
        // ever touched, and the screen could no longer say which ones stayed at their
        // default.
        const changed = Object.fromEntries(Object.entries(this.values()).filter(([key, value]) => this.original[key] !== value));
        if (Object.keys(changed).length === 0) return;

        this.saving.set(true);
        this.error.set(null);
        this.api.updateSettings(changed).subscribe({
            next: () => {
                this.saving.set(false);
                this.saved.set(true);
                this.reload();
            },
            error: (response) => {
                this.saving.set(false);
                // The server's message carries the offending setting's label and the expected
                // value; replacing it with generic text would lose that.
                this.error.set(messageOf(response, 'Saving failed.'));
            }
        });
    }

    saveToken(): void {
        this.savingToken.set(true);
        this.error.set(null);
        this.api.setTicketToken(this.tokenInput).subscribe({
            next: ({ configured }) => {
                this.savingToken.set(false);
                this.tokenConfigured.set(configured);
                // Cleared from the model at the same time as from the field: keeping it would
                // leave the value reachable in the open tab, as for an API key.
                this.tokenInput = '';
                this.saved.set(true);
            },
            error: (response) => {
                this.savingToken.set(false);
                this.error.set(messageOf(response, 'Saving the token failed.'));
            }
        });
    }

    private reload(): void {
        this.api.ticketTokenState().subscribe({
            next: ({ configured }) => this.tokenConfigured.set(configured),
            error: () => this.tokenConfigured.set(false)
        });

        this.api.settings().subscribe({
            next: ({ settings }) => {
                this.catalog.set(settings);
                const values = Object.fromEntries(settings.map((setting) => [setting.key, setting.value]));
                this.values.set(values);
                this.original = { ...values };
            },
            error: () => this.error.set('Could not load the settings.')
        });
    }
}
