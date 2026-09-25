import { CommonModule } from '@angular/common';
import { Component, DestroyRef, inject, input, signal, ChangeDetectionStrategy } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { ToggleSwitchModule } from '@openng/optimus-ui/toggleswitch';
import { messageOf } from '../../core/api-error';
import { IntegrationsApi } from '../../core/api/integrations.api';
import type { SiemConfig, SiemTestResult } from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { SettingsState } from './settings-state';

/**
 * The Integrations tab's SIEM forwarder card.
 *
 * <p>Hidden with its tab rather than destroyed with it, like the tracker cards: an endpoint being
 * typed survives a look at another tab.
 */
@Component({
    selector: 'app-settings-siem',
    standalone: true,
    imports: [
        CommonModule,
        FormsModule,
        ButtonModule,
        CardModule,
        InputTextModule,
        MessageModule,
        ToggleSwitchModule,
        TranslatePipe
    ],
    templateUrl: './settings-siem.html',
    changeDetection: ChangeDetectionStrategy.Eager,
    host: { class: 'contents' }
})
export class SettingsSiem {
    private readonly integrationsApi = inject(IntegrationsApi);
    private readonly i18n = inject(I18nService);
    private readonly state = inject(SettingsState);

    readonly active = input.required<boolean>();

    readonly siemConfig = signal<SiemConfig | null>(null);
    readonly savingSiem = signal(false);
    readonly testingSiem = signal(false);
    readonly siemTestResult = signal<SiemTestResult | null>(null);
    siemForm = {
        enabled: false,
        // The four protocols the server accepts, not the one the form starts on: typed as the
        // literal 'WEBHOOK', the form could not hold a syslog configuration it had just loaded,
        // and an `as any` further down was what kept that quiet.
        protocol: 'WEBHOOK' as SiemConfig['protocol'],
        endpoint: '',
        authHeader: '',
        minSeverity: 'HIGH'
    };

    constructor() {
        this.state.register(() => this.load(), inject(DestroyRef));
    }

    saveSiemConfig(): void {
        this.savingSiem.set(true);
        this.state.error.set(null);
        this.integrationsApi
            .updateSiemConfig({
                enabled: this.siemForm.enabled,
                protocol: this.siemForm.protocol,
                endpoint: this.siemForm.endpoint.trim(),
                authHeader: this.siemForm.authHeader.trim() || undefined,
                minSeverity: this.siemForm.minSeverity
            })
            .subscribe({
                next: (cfg) => {
                    this.savingSiem.set(false);
                    this.siemConfig.set(cfg);
                    this.state.saved.set(true);
                },
                error: (response) => {
                    this.savingSiem.set(false);
                    this.state.error.set(messageOf(response, this.i18n.t('settings.error_save_siem')));
                }
            });
    }

    testSiem(): void {
        if (!this.siemForm.endpoint.trim()) {
            this.siemTestResult.set({
                success: false,
                message: this.i18n.t('settings.siem_endpoint_required'),
                statusCode: 0
            });
            return;
        }
        this.testingSiem.set(true);
        this.siemTestResult.set(null);
        this.integrationsApi
            .testSiemConnection({
                endpoint: this.siemForm.endpoint.trim(),
                authHeader: this.siemForm.authHeader.trim() || undefined
            })
            .subscribe({
                next: (res) => {
                    this.testingSiem.set(false);
                    this.siemTestResult.set(res);
                },
                error: () => {
                    this.testingSiem.set(false);
                    this.siemTestResult.set({
                        success: false,
                        message: this.i18n.t('settings.error_connection_test_request'),
                        statusCode: 0
                    });
                }
            });
    }

    private load(): void {
        this.integrationsApi.getSiemConfig().subscribe({
            next: (cfg) => {
                this.siemConfig.set(cfg);
                this.siemForm = {
                    enabled: cfg.enabled,
                    protocol: cfg.protocol || 'WEBHOOK',
                    endpoint: cfg.endpoint ?? '',
                    authHeader: '',
                    minSeverity: cfg.minSeverity || 'HIGH'
                };
            },
            error: () => this.siemConfig.set(null)
        });
    }
}
