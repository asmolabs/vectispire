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
import type { OllamaCheck, SettingDefinition, SiemConfig, SiemTestResult, ThreatIntelSyncStatus } from '../../core/api.models';

const SEVERITIES = [
    { label: 'Critical', value: 'critical' },
    { label: 'High', value: 'high' },
    { label: 'Medium', value: 'medium' },
    { label: 'Low', value: 'low' }
];

import { TranslatePipe } from '../../core/i18n/translate.pipe';

@Component({
    selector: 'app-settings',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, CardModule, InputNumberModule, InputTextModule, MessageModule, SelectModule, ToggleSwitchModule, TranslatePipe],
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

    readonly webhookSecretConfigured = signal(false);
    readonly savingWebhookSecret = signal(false);
    webhookSecretInput = '';

    readonly siemConfig = signal<SiemConfig | null>(null);
    readonly savingSiem = signal(false);
    readonly testingSiem = signal(false);
    readonly siemTestResult = signal<SiemTestResult | null>(null);
    siemForm = {
        enabled: false,
        protocol: 'WEBHOOK' as const,
        endpoint: '',
        authHeader: '',
        minSeverity: 'HIGH'
    };

    readonly threatIntelStatus = signal<ThreatIntelSyncStatus | null>(null);
    readonly syncingThreatIntel = signal(false);
    readonly threatIntelFeedback = signal<string | null>(null);

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

    saveSiemConfig(): void {
        this.savingSiem.set(true);
        this.error.set(null);
        this.api.updateSiemConfig({
            enabled: this.siemForm.enabled,
            protocol: this.siemForm.protocol,
            endpoint: this.siemForm.endpoint.trim(),
            authHeader: this.siemForm.authHeader.trim() || undefined,
            minSeverity: this.siemForm.minSeverity
        }).subscribe({
            next: (cfg) => {
                this.savingSiem.set(false);
                this.siemConfig.set(cfg);
                this.saved.set(true);
            },
            error: (response) => {
                this.savingSiem.set(false);
                this.error.set(messageOf(response, 'Saving SIEM configuration failed.'));
            }
        });
    }

    testSiem(): void {
        if (!this.siemForm.endpoint.trim()) {
            this.siemTestResult.set({ success: false, message: 'Please provide an Endpoint URL first.', statusCode: 0 });
            return;
        }
        this.testingSiem.set(true);
        this.siemTestResult.set(null);
        this.api.testSiemConnection({
            endpoint: this.siemForm.endpoint.trim(),
            authHeader: this.siemForm.authHeader.trim() || undefined
        }).subscribe({
            next: (res) => {
                this.testingSiem.set(false);
                this.siemTestResult.set(res);
            },
            error: () => {
                this.testingSiem.set(false);
                this.siemTestResult.set({ success: false, message: 'Connection test request failed.', statusCode: 0 });
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

    saveWebhookSecret(): void {
        this.savingWebhookSecret.set(true);
        this.error.set(null);
        this.api.setWebhookSecret(this.webhookSecretInput).subscribe({
            next: ({ configured }) => {
                this.savingWebhookSecret.set(false);
                this.webhookSecretConfigured.set(configured);
                // Cleared from the model as well as from the field: this is the only thing that
                // tells a receiver a message came from Zanshin, so anyone who reads it off the
                // open tab can forge one.
                this.webhookSecretInput = '';
                this.saved.set(true);
            },
            error: (response) => {
                this.savingWebhookSecret.set(false);
                this.error.set(messageOf(response, 'Saving the secret failed.'));
            }
        });
    }

    syncThreatIntel(): void {
        this.syncingThreatIntel.set(true);
        this.threatIntelFeedback.set(null);
        this.api.syncThreatIntel().subscribe({
            next: (status) => {
                this.syncingThreatIntel.set(false);
                this.threatIntelStatus.set(status);
                this.threatIntelFeedback.set(`Synchronized ${status.totalCves} CVEs (${status.totalKev} active CISA KEV). Re-evaluated ${status.backlogUpdatedCount} backlog issues.`);
            },
            error: () => {
                this.syncingThreatIntel.set(false);
                this.threatIntelFeedback.set('Failed to synchronize Threat Intelligence feed.');
            }
        });
    }

    private reload(): void {
        this.api.ticketTokenState().subscribe({
            next: ({ configured }) => this.tokenConfigured.set(configured),
            error: () => this.tokenConfigured.set(false)
        });

        this.api.webhookSecretState().subscribe({
            next: ({ configured }) => this.webhookSecretConfigured.set(configured),
            error: () => this.webhookSecretConfigured.set(false)
        });

        this.api.getThreatIntelStatus().subscribe({
            next: (status) => this.threatIntelStatus.set(status),
            error: () => this.threatIntelStatus.set(null)
        });

        this.api.getSiemConfig().subscribe({
            next: (cfg) => {
                this.siemConfig.set(cfg);
                this.siemForm = {
                    enabled: cfg.enabled,
                    protocol: (cfg.protocol as any) || 'WEBHOOK',
                    endpoint: cfg.endpoint ?? '',
                    authHeader: '',
                    minSeverity: cfg.minSeverity || 'HIGH'
                };
            },
            error: () => this.siemConfig.set(null)
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
