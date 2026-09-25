import { CommonModule } from '@angular/common';
import { Component, computed, inject, input, signal, ChangeDetectionStrategy } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputNumberModule } from '@openng/optimus-ui/inputnumber';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { SelectModule } from '@openng/optimus-ui/select';
import { ToggleSwitchModule } from '@openng/optimus-ui/toggleswitch';
import type { SettingDefinition } from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { SessionStore } from '../../core/session.store';
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
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, CardModule, DialogModule, InputNumberModule, InputTextModule, SelectModule, ToggleSwitchModule, TranslatePipe, SettingsModelReview],
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
        return [
            { label: this.i18n.t('settings.ai_provider_ollama'), value: 'ollama' },
            { label: this.i18n.t('settings.ai_provider_openai'), value: 'openai' }
        ];
    });

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
            (setting) => !WRITE_ONLY_SECRETS.has(setting.key) && !SERVER_STAMPED.has(setting.key));
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

        if (firstKey.startsWith('sla_') || firstKey.startsWith('retention_') || firstKey.startsWith('eol_')
            || lowerName.includes('sla') || lowerName.includes('remediation') || lowerName.includes('retention')
            || lowerName.includes('end of life')) {
            return 'general';
        }
        if (firstKey.startsWith('scanner_') || firstKey.startsWith('sast_') || firstKey.startsWith('source_code')
            || lowerName.includes('scanner') || lowerName.includes('source code')) {
            return 'scanners';
        }
        if (firstKey.startsWith('ai_review_') || lowerName.includes('model') || lowerName.includes('ai')
            || lowerName.includes('ollama') || lowerName.includes('owasp')) {
            return 'ai';
        }
        if (firstKey.startsWith('ticket_') || firstKey.startsWith('notification_') || firstKey.startsWith('webhook_')
            || lowerName.includes('ticket') || lowerName.includes('notification')) {
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
        return (setting.governor_only && !this.session.governsPlatform())
            || (setting.administrator_only && !this.session.isAdmin());
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

    asNumber(value: string): number {
        const parsed = Number(value);
        return Number.isFinite(parsed) ? parsed : 0;
    }

    /** `p-inputnumber` yields `null` when the field is cleared; the server refuses empty. */
    numberToText(value: number | null): string {
        return value === null || value === undefined ? '0' : String(value);
    }
}
