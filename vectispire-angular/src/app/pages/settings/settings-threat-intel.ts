import { CommonModule } from '@angular/common';
import { Component, DestroyRef, inject, input, signal, ChangeDetectionStrategy } from '@angular/core';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { MessageModule } from '@openng/optimus-ui/message';
import { IntelApi } from '../../core/api/intel.api';
import type { ThreatIntelSyncStatus } from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { SettingsState } from './settings-state';

/**
 * The Threat Intelligence tab's feed card: its status, and the button that syncs it now.
 *
 * <p>Hidden with its tab rather than destroyed with it, so the feedback of a sync just run is
 * still there after a look at another tab, as it was when this was part of one component.
 */
@Component({
    selector: 'app-settings-threat-intel',
    standalone: true,
    imports: [CommonModule, ButtonModule, CardModule, MessageModule, TranslatePipe],
    templateUrl: './settings-threat-intel.html',
    changeDetection: ChangeDetectionStrategy.Eager,
    host: { class: 'contents' }
})
export class SettingsThreatIntel {
    private readonly intelApi = inject(IntelApi);
    private readonly i18n = inject(I18nService);
    private readonly state = inject(SettingsState);

    readonly active = input.required<boolean>();

    readonly threatIntelStatus = signal<ThreatIntelSyncStatus | null>(null);
    readonly syncingThreatIntel = signal(false);
    readonly threatIntelFeedback = signal<string | null>(null);

    constructor() {
        this.state.register(() => this.load(), inject(DestroyRef));
    }

    syncThreatIntel(): void {
        this.syncingThreatIntel.set(true);
        this.threatIntelFeedback.set(null);
        this.intelApi.syncThreatIntel().subscribe({
            next: (status) => {
                this.syncingThreatIntel.set(false);
                this.threatIntelStatus.set(status);
                this.threatIntelFeedback.set(this.i18n.t('settings.threat_intel_synced', { cves: status.totalCves, kev: status.totalKev, issues: status.backlogUpdatedCount }));
            },
            error: () => {
                this.syncingThreatIntel.set(false);
                this.threatIntelFeedback.set(this.i18n.t('settings.error_threat_intel_sync'));
            }
        });
    }

    private load(): void {
        this.intelApi.getThreatIntelStatus().subscribe({
            next: (status) => this.threatIntelStatus.set(status),
            error: () => this.threatIntelStatus.set(null)
        });
    }
}
