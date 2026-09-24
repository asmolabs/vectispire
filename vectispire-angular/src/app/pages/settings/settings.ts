import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal, ChangeDetectionStrategy } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { MessageModule } from '@openng/optimus-ui/message';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { I18nService } from '../../core/i18n/i18n.service';
import { SettingsCatalog } from './settings-catalog';
import { SettingsSiem } from './settings-siem';
import { SettingsState, type SettingsTab } from './settings-state';
import { SettingsThreatIntel } from './settings-threat-intel';
import { SettingsTicketing } from './settings-ticketing';

export type { SettingsTab } from './settings-state';

/**
 * The settings screen: the header, the tabs, the banners every section reports to, and the
 * sections themselves.
 *
 * <p>Split into one component per group of cards the template already drew — the catalogue (with
 * the model review block inside its card), the tracker, the SIEM forwarder and the threat feed —
 * once the single component had reached six hundred lines for six unrelated forms. What they share
 * is in {@link SettingsState}, provided here so that it dies with the page.
 */
@Component({
    selector: 'app-settings',
    standalone: true,
    imports: [CommonModule, ButtonModule, MessageModule, TranslatePipe, SettingsCatalog, SettingsTicketing, SettingsSiem, SettingsThreatIntel],
    providers: [SettingsState],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './settings.html'
})
export class Settings {
    private readonly route = inject(ActivatedRoute);
    private readonly router = inject(Router);
    private readonly i18n = inject(I18nService);
    readonly state = inject(SettingsState);

    readonly activeTab = signal<SettingsTab>('general');

    readonly tabs = computed(() => {
        this.i18n.translations();
        return [
            { id: 'general' as const, label: this.i18n.t('settings.tabs.general'), icon: 'pi pi-cog' },
            { id: 'scanners' as const, label: this.i18n.t('settings.tabs.scanners'), icon: 'pi pi-sliders-h' },
            { id: 'ai' as const, label: this.i18n.t('settings.tabs.ai'), icon: 'pi pi-sparkles' },
            { id: 'integrations' as const, label: this.i18n.t('settings.tabs.integrations'), icon: 'pi pi-link' },
            { id: 'threat-intel' as const, label: this.i18n.t('settings.tabs.threat_intel'), icon: 'pi pi-globe' },
            { id: 'governance' as const, label: this.i18n.t('settings.tabs.governance'), icon: 'pi pi-balance-scale' }
        ];
    });

    constructor() {
        this.route.queryParamMap.subscribe((params) => {
            const tab = params.get('tab') as SettingsTab | null;
            if (tab === 'scanners' || tab === 'ai' || tab === 'integrations'
                    || tab === 'threat-intel' || tab === 'governance') {
                this.activeTab.set(tab);
            } else {
                this.activeTab.set('general');
            }
        });
        this.state.reload();
    }

    selectTab(tab: SettingsTab): void {
        this.activeTab.set(tab);
        this.router.navigate([], {
            relativeTo: this.route,
            queryParams: { tab: tab === 'general' ? null : tab },
            queryParamsHandling: 'merge'
        });
    }
}
