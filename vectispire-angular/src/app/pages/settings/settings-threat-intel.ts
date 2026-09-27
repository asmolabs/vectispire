import { CommonModule } from '@angular/common';
import { Component, DestroyRef, computed, inject, input, signal, ChangeDetectionStrategy } from '@angular/core';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { MessageModule } from '@openng/optimus-ui/message';
import { IntelApi } from '../../core/api/intel.api';
import type { ThreatIntelSyncStatus } from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { SettingsState } from './settings-state';

/**
 * The Threat Intelligence tab's feed card: where the CISA KEV catalogue and FIRST's EPSS file stand —
 * when each was last read, how old what was read is, whether the last attempt worked — and the button
 * that syncs both now.
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

    /**
     * The feed's state, as the control plane states it. It fell back to "SYNCED" when the status
     * could not be read, which put a green word on the one tile that exists to say whether the
     * exploitation flags can be trusted.
     */
    readonly stateLabel = computed(() => this.labelOf(this.threatIntelStatus()?.status));

    readonly stateClass = computed(() => stateClass(this.threatIntelStatus()?.status));

    /** The EPSS file's state; absent while the status is unread, never defaulted to anything green. */
    readonly epss = computed(() => this.threatIntelStatus()?.epss ?? null);

    readonly epssStateLabel = computed(() => this.labelOf(this.epss()?.status));

    readonly epssStateClass = computed(() => stateClass(this.epss()?.status));

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
                // A failed attempt answers 200 with its reason: the data in use is kept, and the warning
                // under the tiles says why it was not replaced. The two feeds fail apart, so each says
                // its own outcome.
                const kev =
                    status.status === 'SYNCED'
                        ? this.i18n.t('settings.threat_intel_synced', {
                              cves: status.totalCves,
                              kev: status.totalKev,
                              issues: status.backlogUpdatedCount
                          })
                        : this.i18n.t('settings.error_threat_intel_sync');
                // In progress first: a request made while another synchronisation writes is not run,
                // and the status it answers is the previous one's.
                const epss = status.epss.inProgress
                    ? this.i18n.t('settings.epss_in_progress')
                    : status.epss.status === 'SYNCED'
                      ? this.i18n.t('settings.epss_synced', {
                            count: status.epss.totalScored,
                            issues: status.epss.backlogUpdatedCount
                        })
                      : this.i18n.t('settings.error_epss_sync');
                this.threatIntelFeedback.set(kev + ' ' + epss);
            },
            error: () => {
                this.syncingThreatIntel.set(false);
                this.threatIntelFeedback.set(this.i18n.t('settings.error_threat_intel_sync'));
            }
        });
    }

    private labelOf(state: string | undefined): string {
        switch (state) {
            case 'SYNCED':
                return this.i18n.t('settings.feed_state_synced');
            case 'FAILED':
                return this.i18n.t('settings.feed_state_failed');
            case 'NEVER_SYNCED':
                return this.i18n.t('settings.feed_state_never_synced');
            default:
                return this.i18n.t('settings.feed_state_unknown');
        }
    }

    private load(): void {
        this.intelApi.getThreatIntelStatus().subscribe({
            next: (status) => this.threatIntelStatus.set(status),
            error: () => this.threatIntelStatus.set(null)
        });
    }
}

function stateClass(state: string | undefined): string {
    switch (state) {
        case 'SYNCED':
            return 'text-green-600 dark:text-green-400';
        case 'FAILED':
            return 'text-red-600 dark:text-red-400';
        default:
            return 'text-muted-color';
    }
}
