import { Component, DestroyRef, computed, inject, input, signal, ChangeDetectionStrategy } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputNumberModule } from '@openng/optimus-ui/inputnumber';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { SelectModule } from '@openng/optimus-ui/select';
import { ToggleSwitchModule } from '@openng/optimus-ui/toggleswitch';
import type { SettingDefinition, TicketCaState } from '../../core/api.models';
import { SettingsApi } from '../../core/api/settings.api';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { SessionStore } from '../../core/session.store';
import {
    INTEGRATIONS_ROUTE,
    IntegrationRegistry,
    NOTIFICATION_SETTING_INTEGRATIONS,
    aiIntegration,
    trackerIntegration
} from '../../shared/integrations';
import { SettingsModelReview } from './settings-model-review';
import { SettingsState, type SettingsTab } from './settings-state';

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
 * The server's settings catalogue, one card per section, on the tab each section belongs to.
 *
 * <p>The risk dialog lives here and not with the model review block, because what opens it is a
 * switch in the generic list below that block.
 */
@Component({
    selector: 'app-settings-catalog',
    imports: [
        DatePipe,
        FormsModule,
        RouterLink,
        ButtonModule,
        CardModule,
        DialogModule,
        InputNumberModule,
        InputTextModule,
        SelectModule,
        ToggleSwitchModule,
        TranslatePipe,
        SettingsModelReview
    ],
    templateUrl: './settings-catalog.html',
    // No box of its own: the cards lay out exactly as they did when they were the page's children.
    changeDetection: ChangeDetectionStrategy.Eager,
    host: { class: 'contents' }
})
export class SettingsCatalog {
    private readonly i18n = inject(I18nService);
    readonly session = inject(SessionStore);
    readonly state = inject(SettingsState);

    readonly tab = input.required<SettingsTab>();

    private readonly settingsApi = inject(SettingsApi);

    /**
     * What the tracker CA pins, read from the server rather than parsed here: the subject and the expiry are
     * the ones the calls will check, as the forge connections show theirs. Asked for by an administrator
     * only — the route is theirs, like the value in the catalogue.
     */
    readonly ticketCa = signal<TicketCaState | null>(null);

    readonly integrationsRoute = INTEGRATIONS_ROUTE;

    /**
     * Which AI providers, notification channels and trackers the platform governor has switched on
     * (decision 0040): a disabled one is not offered for a new choice, and one already configured reads
     * suspended, with the way to the screen that switches it back on.
     */
    readonly registry = new IntegrationRegistry();

    constructor() {
        this.state.register(() => {
            this.loadTicketCa();
            this.registry.load();
        }, inject(DestroyRef));
    }

    private loadTicketCa(): void {
        if (!this.session.isAdmin()) {
            this.ticketCa.set(null);
            return;
        }
        this.settingsApi.ticketCaState().subscribe({
            next: (state) => this.ticketCa.set(state),
            error: () => this.ticketCa.set(null)
        });
    }

    readonly severities = computed(() => {
        this.i18n.translations();
        return [
            { label: this.i18n.t('severities.critical'), value: 'critical' },
            { label: this.i18n.t('severities.high'), value: 'high' },
            { label: this.i18n.t('severities.medium'), value: 'medium' },
            { label: this.i18n.t('severities.low'), value: 'low' }
        ];
    });

    /**
     * The two wire protocols, offered as a list so the provider is picked rather than typed.
     *
     * <p>A computed, like the page's `tabs` and for the same reason: these labels are the only two
     * on this screen that were English literals, so a French operator picked their model provider
     * from an untranslated list. Reading `translations()` is what makes the list redraw when the
     * language changes rather than keeping whatever was loaded first.
     */
    readonly aiProviders = computed(() => {
        this.i18n.translations();
        const stored = this.stored('ai_review_provider');
        return [
            { label: this.i18n.t('settings.ai_provider_ollama'), value: 'ollama' },
            { label: this.i18n.t('settings.ai_provider_openai'), value: 'openai' }
        ]
            .filter((option) => this.registry.offers(aiIntegration(option.value), aiIntegration(stored)))
            .map((option) => this.markSuspended(option, aiIntegration(option.value)));
    });

    /**
     * The trackers, offered as a list like the AI provider rather than typed: the five values the server
     * reads, less those the platform governor has switched off. `none` is always offered — choosing no
     * tracker is always saved.
     */
    readonly trackers = computed(() => {
        this.i18n.translations();
        const stored = this.stored('ticket_provider');
        return (
            [
                { label: this.i18n.t('settings.ticket_provider_none'), value: 'none' },
                { label: this.i18n.t('settings.ticket_provider_gitlab'), value: 'gitlab' },
                { label: this.i18n.t('settings.ticket_provider_github'), value: 'github' },
                { label: this.i18n.t('settings.ticket_provider_jira'), value: 'jira' },
                { label: this.i18n.t('settings.ticket_provider_servicenow'), value: 'servicenow' }
            ]
                .filter(
                    (option) =>
                        option.value === 'none' ||
                        this.registry.offers(trackerIntegration(option.value), trackerIntegration(stored))
                )
                .map((option) =>
                    option.value === 'none' ? option : this.markSuspended(option, trackerIntegration(option.value))
                )
                // A value a newer server reads and this list does not: shown as stored, never as a blank choice.
                .concat(
                    stored && !['none', 'gitlab', 'github', 'jira', 'servicenow'].includes(stored)
                        ? [{ label: stored, value: stored }]
                        : []
                )
        );
    });

    /** The value the server holds, not the one being typed: what is configured is what can be suspended. */
    private stored(key: string): string {
        return this.state.catalog().find((setting) => setting.key === key)?.value ?? '';
    }

    private markSuspended(option: { label: string; value: string }, integration: string) {
        return this.registry.isDisabled(integration)
            ? { ...option, label: this.i18n.t('integrations.option_suspended', { name: option.label }) }
            : option;
    }

    /**
     * Where a setting stands against the registry: the integration it configures is switched off and it is
     * configured (`suspended` — kept, and resumed when switched back on), or switched off and empty
     * (`unavailable` — not offered for a new choice). `null` for a setting no switch concerns.
     */
    integrationState(setting: SettingDefinition): { integration: string; state: 'suspended' | 'unavailable' } | null {
        const integration = this.integrationOf(setting);
        if (!integration || !this.registry.isDisabled(integration)) return null;
        return { integration, state: this.configures(setting) ? 'suspended' : 'unavailable' };
    }

    private integrationOf(setting: SettingDefinition): string | null {
        if (setting.key === 'ai_review_provider') return aiIntegration(setting.value || 'ollama');
        if (setting.key === 'ticket_provider') {
            return setting.value && setting.value !== 'none' ? trackerIntegration(setting.value) : null;
        }
        return NOTIFICATION_SETTING_INTEGRATIONS[setting.key] ?? null;
    }

    /** A channel's URL or recipients set, its switch on, a provider or a tracker chosen. */
    private configures(setting: SettingDefinition): boolean {
        if (setting.type === 'boolean') return setting.value === 'true';
        return setting.value.trim() !== '';
    }

    /** A notification channel switched off and not configured: its field offers nothing to fill in. */
    isUnavailable(setting: SettingDefinition): boolean {
        return this.integrationState(setting)?.state === 'unavailable' && setting.key.startsWith('notification_');
    }

    readonly riskConfirmVisible = signal(false);

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

    /** The rows this card renders: everything but the write-only secrets. See {@link WRITE_ONLY_SECRETS}. */
    visibleSettings(section: { settings: SettingDefinition[] }): SettingDefinition[] {
        return section.settings.filter(
            (setting) => !WRITE_ONLY_SECRETS.has(setting.key) && !SERVER_STAMPED.has(setting.key)
        );
    }

    /**
     * Asks before opening the public endpoint, never before closing it.
     *
     * <p>The confirmation is on the dangerous direction only. A dialog in front of "stop sending
     * our code to a third party" trains people to dismiss the one in front of "start".
     */
    setAllowRemote(enabled: boolean): void {
        if (!enabled) {
            this.state.set('ai_review_allow_remote_url', 'false');
            return;
        }
        this.riskConfirmVisible.set(true);
    }

    confirmRiskAndAllowRemote(): void {
        this.riskConfirmVisible.set(false);
        // Only the switch is set here. The name and the date against it are the server's to write,
        // on the save that follows — this screen cannot be the source of its own acknowledgement.
        this.state.set('ai_review_allow_remote_url', 'true');
    }

    /**
     * The tab a section shows on — and there is always one.
     *
     * <p><b>Three sections showed nowhere.</b> This method was a per-tab allow list ending in a
     * {@code return false}: a section no rule claimed vanished from the screen with no error, no
     * empty tab, nothing. `Access`, `VEX Triage & Approval` and `Licenses` were in that position —
     * including four-eyes, which decides whether a triage decision settles or goes to approval, and
     * target visibility. Two audited governance rules, settable only by an API call.
     *
     * <p><b>The last tab catches instead of claiming</b>, and that is the real fix: the defect was
     * not that these three sections were missing from a list, it was that a list could lose any. A
     * section added tomorrow will appear under "Governance" — in the wrong place perhaps, never
     * nowhere.
     */
    private tabOf(section: { name: string; settings: SettingDefinition[] }): SettingsTab {
        const firstKey = section.settings[0]?.key ?? '';
        const lowerName = section.name.toLowerCase();

        if (
            firstKey.startsWith('sla_') ||
            firstKey.startsWith('retention_') ||
            firstKey.startsWith('eol_') ||
            lowerName.includes('sla') ||
            lowerName.includes('remediation') ||
            lowerName.includes('retention') ||
            lowerName.includes('end of life')
        ) {
            return 'general';
        }
        if (
            firstKey.startsWith('scanner_') ||
            firstKey.startsWith('sast_') ||
            firstKey.startsWith('source_code') ||
            firstKey.startsWith('scan_default_') ||
            lowerName.includes('scanner') ||
            lowerName.includes('scheduling') ||
            lowerName.includes('source code')
        ) {
            return 'scanners';
        }
        if (
            firstKey.startsWith('ai_review_') ||
            lowerName.includes('model') ||
            lowerName.includes('ai') ||
            lowerName.includes('ollama') ||
            lowerName.includes('owasp')
        ) {
            return 'ai';
        }
        if (
            firstKey.startsWith('ticket_') ||
            firstKey.startsWith('notification_') ||
            firstKey.startsWith('webhook_') ||
            lowerName.includes('ticket') ||
            lowerName.includes('notification')
        ) {
            return 'integrations';
        }
        if (firstKey.startsWith('enrichment_') || lowerName.includes('enrichment') || lowerName.includes('threat')) {
            return 'threat-intel';
        }
        return 'governance';
    }

    isSectionVisible(section: { name: string; settings: SettingDefinition[] }): boolean {
        return this.tabOf(section) === this.tab();
    }

    /**
     * This setting decides a rule and this account does not govern the platform, or it decides
     * where a credential is sent and this account may not set that credential.
     */
    isReadOnlyHere(setting: SettingDefinition): boolean {
        return (
            (setting.governor_only && !this.session.governsPlatform()) ||
            (setting.administrator_only && !this.session.isAdmin())
        );
    }

    getSectionTitle(section: { name: string; settings: SettingDefinition[] }): string {
        this.i18n.translations();
        const firstKey = section.settings[0]?.key ?? '';
        if (firstKey.startsWith('sla_')) return this.i18n.t('settings.sections.remediation_slas');
        if (firstKey.startsWith('scanner_')) return this.i18n.t('settings.sections.scanner_engine');
        if (firstKey.startsWith('eol_')) return this.i18n.t('settings.sections.end_of_life');
        if (firstKey.startsWith('scan_default_')) return this.i18n.t('settings.sections.scheduling');
        if (firstKey.startsWith('sast_') || firstKey.startsWith('source_code'))
            return this.i18n.t('settings.sections.source_code');
        if (firstKey.startsWith('enrichment_')) return this.i18n.t('settings.sections.enrichment');
        if (firstKey.startsWith('ai_review_')) return this.i18n.t('settings.sections.local_ai');
        if (firstKey.startsWith('ticket_')) return this.i18n.t('settings.sections.ticketing');
        if (firstKey.startsWith('notification_') || firstKey.startsWith('webhook_'))
            return this.i18n.t('settings.sections.notifications');
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

    asNumber(value: string): number {
        const parsed = Number(value);
        return Number.isFinite(parsed) ? parsed : 0;
    }

    /** `p-inputnumber` yields `null` when the field is cleared; the server refuses empty. */
    numberToText(value: number | null): string {
        return value === null || value === undefined ? '0' : String(value);
    }
}
