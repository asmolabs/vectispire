import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputNumberModule } from '@openng/optimus-ui/inputnumber';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { ToggleSwitchModule } from '@openng/optimus-ui/toggleswitch';
import { messageOf } from '../../core/api-error';
import { ApiService } from '../../core/api.service';
import type { OllamaCheck, SettingDefinition, SiemConfig, SiemTestResult, ThreatIntelSyncStatus } from '../../core/api.models';

/**
 * Settings that are written through their own route and must never appear in the generic form.
 *
 * <p>A secret rendered by the catalog is a secret the generic save path will write in clear and
 * the audit log will record by value — that path stores what it is handed and names every change
 * `key = value`. Each is encrypted at rest by a route of its own, and has a field on this
 * screen that shows "configured" instead of the value. The server refuses them on the generic
 * route as well — this list keeps the form from offering an input that would only ever error.
 */
const WRITE_ONLY_SECRETS = new Set([
    'ticket_token',
    'notification_webhook_secret',
    'ticket_webhook_secret',
    'ai_review_openai_key'
]);

/**
 * Settings the server stamps and the form may only display.
 *
 * <p>They are in the catalog so this screen can show who accepted the data-leak risk and when —
 * and out of the generic list because an editable field would let the person who opened the public
 * endpoint also write whose decision it was. The server refuses them on the wire as well; this set
 * is what keeps the screen from offering an input that would only ever produce an error.
 */
const SERVER_STAMPED = new Set(['ai_review_risk_acknowledged_by', 'ai_review_risk_acknowledged_at']);

/**
 * Whether a URL names this machine or its own network — a best-effort read, for a warning only.
 *
 * <p><b>Never the authority.</b> The server's outbound guard resolves the name and decides; this
 * exists so the screen can warn while the operator types, before anything is saved. It errs
 * towards "not local": a banner that appears when it need not is a question, and one that stays
 * hidden when it should not is a leak nobody was told about.
 */
function isLocalEndpoint(url: string): boolean {
    let host: string;
    try {
        host = new URL(url.trim()).hostname.toLowerCase();
    } catch {
        return false;
    }
    if (host === 'localhost' || host.endsWith('.localhost') || host === '::1' || host.endsWith('.internal')) {
        return true;
    }
    if (host === '127.0.0.1' || host.startsWith('127.')) {
        return true;
    }
    // The private IPv4 ranges, and IPv6 unique-local.
    return /^10\./.test(host)
        || /^192\.168\./.test(host)
        || /^172\.(1[6-9]|2\d|3[01])\./.test(host)
        || /^f[cd][0-9a-f]{2}:/.test(host);
}

const SEVERITIES = [
    { label: 'Critical', value: 'critical' },
    { label: 'High', value: 'high' },
    { label: 'Medium', value: 'medium' },
    { label: 'Low', value: 'low' }
];

import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { I18nService } from '../../core/i18n/i18n.service';

export type SettingsTab = 'general' | 'scanners' | 'ai' | 'integrations' | 'threat-intel';

@Component({
    selector: 'app-settings',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, CardModule, DialogModule, InputNumberModule, InputTextModule, MessageModule, SelectModule, ToggleSwitchModule, TranslatePipe],
    templateUrl: './settings.html'
})
export class Settings {
    private readonly api = inject(ApiService);
    private readonly route = inject(ActivatedRoute);
    private readonly router = inject(Router);
    private readonly i18n = inject(I18nService);

    readonly activeTab = signal<SettingsTab>('general');

    readonly tabs = computed(() => {
        this.i18n.translations();
        return [
            { id: 'general' as const, label: this.i18n.t('settings.tabs.general'), icon: 'pi pi-cog' },
            { id: 'scanners' as const, label: this.i18n.t('settings.tabs.scanners'), icon: 'pi pi-sliders-h' },
            { id: 'ai' as const, label: this.i18n.t('settings.tabs.ai'), icon: 'pi pi-sparkles' },
            { id: 'integrations' as const, label: this.i18n.t('settings.tabs.integrations'), icon: 'pi pi-link' },
            { id: 'threat-intel' as const, label: this.i18n.t('settings.tabs.threat_intel'), icon: 'pi pi-globe' }
        ];
    });

    readonly severities = computed(() => {
        this.i18n.translations();
        return [
            { label: this.i18n.t('settings.severities.critical'), value: 'critical' },
            { label: this.i18n.t('settings.severities.high'), value: 'high' },
            { label: this.i18n.t('settings.severities.medium'), value: 'medium' },
            { label: this.i18n.t('settings.severities.low'), value: 'low' }
        ];
    });

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
    readonly webhookCopied = signal<string | null>(null);
    webhookSecretInput = '';

    readonly ticketWebhookSecretConfigured = signal(false);
    readonly savingTicketWebhookSecret = signal(false);
    ticketWebhookSecretInput = '';

    readonly openAiKeyConfigured = signal(false);
    readonly savingOpenAiKey = signal(false);
    openAiKeyInput = '';

    /**
     * The two wire protocols, offered as a list so the provider is picked rather than typed.
     *
     * <p>A computed, like `tabs` above and for the same reason: these labels are the only two on
     * this screen that were English literals, so a French operator picked their model provider
     * from an untranslated list. Reading `translations()` is what makes the list redraw when the
     * language changes rather than keeping whatever was loaded first.
     */
    readonly aiProviders = computed(() => {
        this.i18n.translations();
        return [
            { label: this.i18n.t('settings.ai_provider_ollama'), value: 'ollama' },
            { label: this.i18n.t('settings.ai_provider_openai'), value: 'openai' }
        ];
    });

    /** Which one is selected right now, read from the settings the form holds. */
    readonly aiProvider = computed(() => this.values()['ai_review_provider'] ?? 'ollama');

    /** The URL in use, named in the warning so it points at something the operator can check. */
    readonly aiEndpoint = computed(() =>
        this.aiProvider() === 'openai'
            ? (this.values()['ai_review_openai_url'] || 'https://api.openai.com/v1')
            : (this.values()['ai_review_ollama_url'] || 'http://localhost:11434'));

    /**
     * Whether the current configuration permits the code to leave the estate.
     *
     * <p>Two conditions, not one: the acknowledgement is what opens the guard, and the endpoint is
     * what it opens onto. Either alone is not a leak — an acknowledged setting pointing at
     * localhost sends nothing, and OpenAI's address without the acknowledgement is refused before
     * the request is made.
     */
    readonly aiSendsCodeOffSite = computed(() => {
        if (this.values()['ai_review_allow_remote_url'] !== 'true') {
            return false;
        }
        const url = this.aiProvider() === 'openai'
            ? (this.values()['ai_review_openai_url'] ?? '')
            : (this.values()['ai_review_ollama_url'] ?? '');
        return !isLocalEndpoint(url);
    });

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
                    detail: 'The connection test could not be run.',
                    provider: this.aiProvider(),
                    // The check never ran, so it learned nothing about the destination. The banner
                    // above is driven by the form's own values, not by this.
                    remoteAllowed: false
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
        this.route.queryParamMap.subscribe((params) => {
            const tab = params.get('tab') as SettingsTab | null;
            if (tab === 'scanners' || tab === 'ai' || tab === 'integrations' || tab === 'threat-intel') {
                this.activeTab.set(tab);
            } else {
                this.activeTab.set('general');
            }
        });
        this.reload();
    }

    selectTab(tab: SettingsTab): void {
        this.activeTab.set(tab);
        this.router.navigate([], {
            relativeTo: this.route,
            queryParams: { tab: tab === 'general' ? null : tab },
            queryParamsHandling: 'merge'
        });
    }

    /** The rows this card renders: everything but the write-only secrets. See {@link WRITE_ONLY_SECRETS}. */
    visibleSettings(section: { settings: SettingDefinition[] }): SettingDefinition[] {
        return section.settings.filter(
            (setting) => !WRITE_ONLY_SECRETS.has(setting.key) && !SERVER_STAMPED.has(setting.key));
    }

    /** Who accepted the data-leak risk, and when — empty strings when nobody has. */
    readonly riskAcknowledgedBy = computed(() => this.values()['ai_review_risk_acknowledged_by'] ?? '');
    readonly riskAcknowledgedAt = computed(() => this.values()['ai_review_risk_acknowledged_at'] ?? '');

    /**
     * Asks before opening the public endpoint, never before closing it.
     *
     * <p>The confirmation is on the dangerous direction only. A dialog in front of "stop sending
     * our code to a third party" trains people to dismiss the one in front of "start".
     */
    setAllowRemote(enabled: boolean): void {
        if (!enabled) {
            this.set('ai_review_allow_remote_url', 'false');
            return;
        }
        this.riskConfirmVisible.set(true);
    }

    confirmRiskAndAllowRemote(): void {
        this.riskConfirmVisible.set(false);
        // Only the switch is set here. The name and the date against it are the server's to write,
        // on the save that follows — this screen cannot be the source of its own acknowledgement.
        this.set('ai_review_allow_remote_url', 'true');
    }

    readonly riskConfirmVisible = signal(false);

    isSectionVisible(section: { name: string; settings: SettingDefinition[] }): boolean {
        const tab = this.activeTab();
        const firstKey = section.settings[0]?.key ?? '';
        const lowerName = section.name.toLowerCase();

        if (tab === 'general') {
            return firstKey.startsWith('sla_') || firstKey.startsWith('retention_') || firstKey.startsWith('eol_')
                || lowerName.includes('sla') || lowerName.includes('remediation') || lowerName.includes('retention') || lowerName.includes('end of life');
        }
        if (tab === 'scanners') {
            return firstKey.startsWith('scanner_') || firstKey.startsWith('sast_') || firstKey.startsWith('source_code')
                || lowerName.includes('scanner') || lowerName.includes('source code');
        }
        if (tab === 'ai') {
            return firstKey.startsWith('ai_review_') || lowerName.includes('model') || lowerName.includes('ai') || lowerName.includes('ollama') || lowerName.includes('owasp');
        }
        if (tab === 'integrations') {
            return firstKey.startsWith('ticket_') || firstKey.startsWith('notification_') || firstKey.startsWith('webhook_')
                || lowerName.includes('ticket') || lowerName.includes('notification');
        }
        if (tab === 'threat-intel') {
            return firstKey.startsWith('enrichment_') || lowerName.includes('enrichment') || lowerName.includes('threat');
        }
        return false;
    }

    getSectionTitle(section: { name: string; settings: SettingDefinition[] }): string {
        this.i18n.translations();
        const firstKey = section.settings[0]?.key ?? '';
        if (firstKey.startsWith('sla_')) return this.i18n.t('settings.sections.remediation_slas');
        if (firstKey.startsWith('scanner_')) return this.i18n.t('settings.sections.scanner_engine');
        if (firstKey.startsWith('eol_')) return this.i18n.t('settings.sections.end_of_life');
        if (firstKey.startsWith('sast_') || firstKey.startsWith('source_code')) return this.i18n.t('settings.sections.source_code');
        if (firstKey.startsWith('enrichment_')) return this.i18n.t('settings.sections.enrichment');
        if (firstKey.startsWith('ai_review_')) return this.i18n.t('settings.sections.local_ai');
        if (firstKey.startsWith('ticket_')) return this.i18n.t('settings.sections.ticketing');
        if (firstKey.startsWith('notification_') || firstKey.startsWith('webhook_')) return this.i18n.t('settings.sections.notifications');
        if (firstKey.startsWith('retention_')) return this.i18n.t('settings.sections.retention');
        return section.name;
    }

    getSettingLabel(setting: SettingDefinition): string {
        this.i18n.translations();
        const key = `settings.keys.${setting.key}.label`;
        const translated = this.i18n.t(key);
        return translated !== key ? translated : setting.label;
    }

    getSettingHelp(setting: SettingDefinition): string {
        this.i18n.translations();
        const key = `settings.keys.${setting.key}.help`;
        const translated = this.i18n.t(key);
        return translated !== key ? translated : setting.help;
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

    saveTicketWebhookSecret(): void {
        this.savingTicketWebhookSecret.set(true);
        this.error.set(null);
        this.api.setTicketWebhookSecret(this.ticketWebhookSecretInput).subscribe({
            next: ({ configured }) => {
                this.savingTicketWebhookSecret.set(false);
                this.ticketWebhookSecretConfigured.set(configured);
                this.ticketWebhookSecretInput = '';
                this.saved.set(true);
            },
            error: (response) => {
                this.savingTicketWebhookSecret.set(false);
                this.error.set(messageOf(response, 'Saving the webhook secret failed.'));
            }
        });
    }

    saveOpenAiKey(): void {
        this.savingOpenAiKey.set(true);
        this.error.set(null);
        this.api.setOpenAiKey(this.openAiKeyInput).subscribe({
            next: ({ configured }) => {
                this.savingOpenAiKey.set(false);
                this.openAiKeyConfigured.set(configured);
                // Cleared from the model at the same time as from the field, like the tracker
                // token: keeping it would leave the key reachable in the open tab.
                this.openAiKeyInput = '';
                this.saved.set(true);
            },
            error: (response) => {
                this.savingOpenAiKey.set(false);
                this.error.set(messageOf(response, 'Saving the API key failed.'));
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
                // tells a receiver a message came from Vectispire, so anyone who reads it off the
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

    getWebhookUrl(provider: string): string {
        return `${window.location.origin}/api/v1/tickets/webhook/${provider}`;
    }

    copyWebhookUrl(provider: string): void {
        const url = this.getWebhookUrl(provider);
        navigator.clipboard.writeText(url).then(() => {
            this.webhookCopied.set(provider);
            setTimeout(() => this.webhookCopied.set(null), 3000);
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

        this.api.ticketWebhookSecretState().subscribe({
            next: ({ configured }) => this.ticketWebhookSecretConfigured.set(configured),
            error: () => this.ticketWebhookSecretConfigured.set(false)
        });

        this.api.openAiKeyState().subscribe({
            next: ({ configured }) => this.openAiKeyConfigured.set(configured),
            error: () => this.openAiKeyConfigured.set(false)
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
