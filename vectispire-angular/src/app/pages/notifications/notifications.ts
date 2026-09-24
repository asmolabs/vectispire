import { Component, OnInit, signal, inject, ChangeDetectionStrategy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { SessionStore } from '@/app/core/session.store';
import { IntegrationsApi } from '../../core/api/integrations.api';
import { NotificationChannelStatus, NotificationTestResult } from '../../core/api.models';
import { ButtonModule } from '@openng/optimus-ui/button';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { MessageModule } from '@openng/optimus-ui/message';
import { ProgressSpinnerModule } from '@openng/optimus-ui/progressspinner';
import { RouterLink } from '@angular/router';
import { TranslatePipe } from '@/app/core/i18n/translate.pipe';
import { I18nService } from '@/app/core/i18n/i18n.service';

@Component({
    selector: 'app-notifications',
    standalone: true,
    imports: [
        CommonModule,
        FormsModule,
        ButtonModule,
        TableModule,
        TagModule,
        MessageModule,
        ProgressSpinnerModule,
        RouterLink, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './notifications.html'
})
export class Notifications implements OnInit {
    private readonly integrationsApi = inject(IntegrationsApi);
    private readonly session = inject(SessionStore);
    private readonly i18n = inject(I18nService);

    /** Sending a test posts to somebody's Slack, so it belongs to whoever configured it. */
    readonly isSecurityLead = this.session.isSecurityLead;

    readonly channels = signal<NotificationChannelStatus[]>([]);
    readonly loading = signal<boolean>(false);
    readonly error = signal<string | null>(null);
    readonly testingChannel = signal<string | null>(null);
    readonly testResults = signal<Record<string, NotificationTestResult>>({});

    ngOnInit(): void {
        this.loadChannels();
    }

    loadChannels(): void {
        this.loading.set(true);
        this.error.set(null);

        this.integrationsApi.getNotificationChannels().subscribe({
            next: (data) => {
                this.channels.set(data);
                this.loading.set(false);
            },
            error: (err) => {
                this.error.set(err?.error?.message ?? this.i18n.t('notifications.load_failed'));
                this.loading.set(false);
            }
        });
    }

    testChannel(channelType: string): void {
        this.testingChannel.set(channelType);

        this.integrationsApi.testNotificationChannel(channelType).subscribe({
            next: (res) => {
                this.testingChannel.set(null);
                this.testResults.update((current) => ({
                    ...current,
                    [channelType]: res
                }));
            },
            error: (err) => {
                this.testingChannel.set(null);
                this.testResults.update((current) => ({
                    ...current,
                    [channelType]: {
                        type: channelType,
                        success: false,
                        message: err?.error?.message ?? this.i18n.t('notifications.test_failed'),
                        testedAt: new Date().toISOString()
                    }
                }));
            }
        });
    }

    getChannelIcon(type: string): string {
        switch (type) {
            case 'scan_delta_slack': return 'pi pi-slack text-purple-500';
            case 'scan_delta_teams': return 'pi pi-microsoft text-blue-500';
            case 'scan_delta_discord': return 'pi pi-discord text-indigo-500';
            case 'scan_delta_mail': return 'pi pi-envelope text-emerald-500';
            default: return 'pi pi-send text-amber-500';
        }
    }
}
