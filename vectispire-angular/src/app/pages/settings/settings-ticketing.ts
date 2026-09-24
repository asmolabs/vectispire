import { CommonModule } from '@angular/common';
import { Component, DestroyRef, inject, input, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { messageOf } from '../../core/api-error';
import { SettingsApi } from '../../core/api/settings.api';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { SettingsState } from './settings-state';

/**
 * The Integrations tab's tracker cards: the token Vectispire calls the tracker with, the secret the
 * tracker calls back with, and the webhook URLs to give it.
 *
 * <p>Created with the page and hidden with its tab rather than destroyed with it, as when it was
 * part of one component: a half-typed token survives a look at another tab, and the stored state
 * is read once on arrival, not on every visit.
 */
@Component({
    selector: 'app-settings-ticketing',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, CardModule, InputTextModule, TranslatePipe],
    templateUrl: './settings-ticketing.html',
    host: { class: 'contents' }
})
export class SettingsTicketing {
    private readonly settingsApi = inject(SettingsApi);
    private readonly i18n = inject(I18nService);
    private readonly state = inject(SettingsState);

    readonly active = input.required<boolean>();

    readonly tokenConfigured = signal(false);
    readonly savingToken = signal(false);
    tokenInput = '';

    readonly ticketWebhookSecretConfigured = signal(false);
    readonly savingTicketWebhookSecret = signal(false);
    ticketWebhookSecretInput = '';

    // The outbound notification signing secret — the opposite direction from the inbound one
    // above: this signs what Vectispire sends. Held here because it shares the tab and the
    // write-only treatment, not because it belongs to ticketing.
    readonly webhookSecretConfigured = signal(false);
    readonly savingWebhookSecret = signal(false);
    webhookSecretInput = '';

    readonly webhookCopied = signal<string | null>(null);

    constructor() {
        this.state.register(() => this.load(), inject(DestroyRef));
    }

    saveToken(): void {
        this.savingToken.set(true);
        this.state.error.set(null);
        this.settingsApi.setTicketToken(this.tokenInput).subscribe({
            next: ({ configured }) => {
                this.savingToken.set(false);
                this.tokenConfigured.set(configured);
                // Cleared from the model at the same time as from the field: keeping it would
                // leave the value reachable in the open tab, as for an API key.
                this.tokenInput = '';
                this.state.saved.set(true);
            },
            error: (response) => {
                this.savingToken.set(false);
                this.state.error.set(messageOf(response, this.i18n.t('settings.error_save_token')));
            }
        });
    }

    saveTicketWebhookSecret(): void {
        this.savingTicketWebhookSecret.set(true);
        this.state.error.set(null);
        this.settingsApi.setTicketWebhookSecret(this.ticketWebhookSecretInput).subscribe({
            next: ({ configured }) => {
                this.savingTicketWebhookSecret.set(false);
                this.ticketWebhookSecretConfigured.set(configured);
                this.ticketWebhookSecretInput = '';
                this.state.saved.set(true);
            },
            error: (response) => {
                this.savingTicketWebhookSecret.set(false);
                this.state.error.set(messageOf(response, this.i18n.t('settings.error_save_webhook_secret')));
            }
        });
    }

    saveWebhookSecret(): void {
        this.savingWebhookSecret.set(true);
        this.state.error.set(null);
        this.settingsApi.setWebhookSecret(this.webhookSecretInput).subscribe({
            next: ({ configured }) => {
                this.savingWebhookSecret.set(false);
                this.webhookSecretConfigured.set(configured);
                // Cleared from the model as well as from the field: this is the only thing that
                // tells a receiver a message came from Vectispire, so anyone who reads it off the
                // open tab can forge one.
                this.webhookSecretInput = '';
                this.state.saved.set(true);
            },
            error: (response) => {
                this.savingWebhookSecret.set(false);
                this.state.error.set(messageOf(response, this.i18n.t('settings.error_save_secret')));
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

    private load(): void {
        this.settingsApi.ticketTokenState().subscribe({
            next: ({ configured }) => this.tokenConfigured.set(configured),
            error: () => this.tokenConfigured.set(false)
        });

        this.settingsApi.webhookSecretState().subscribe({
            next: ({ configured }) => this.webhookSecretConfigured.set(configured),
            error: () => this.webhookSecretConfigured.set(false)
        });

        this.settingsApi.ticketWebhookSecretState().subscribe({
            next: ({ configured }) => this.ticketWebhookSecretConfigured.set(configured),
            error: () => this.ticketWebhookSecretConfigured.set(false)
        });
    }
}
