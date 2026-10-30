import { Component, DestroyRef, inject, input, signal, ChangeDetectionStrategy } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { TagModule } from '@openng/optimus-ui/tag';
import { messageOf } from '../../core/api-error';
import type { TicketTokenState } from '../../core/api.models';
import { SettingsApi } from '../../core/api/settings.api';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { daysLeft, expiryState, type ExpiryState } from '../../shared/forge-words';
import { INTEGRATIONS_ROUTE } from '../../shared/integrations';
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
    imports: [DatePipe, FormsModule, RouterLink, ButtonModule, CardModule, InputTextModule, TagModule, TranslatePipe],
    templateUrl: './settings-ticketing.html',
    changeDetection: ChangeDetectionStrategy.Eager,
    host: { class: 'contents' }
})
export class SettingsTicketing {
    private readonly settingsApi = inject(SettingsApi);
    private readonly i18n = inject(I18nService);
    private readonly state = inject(SettingsState);

    readonly active = input.required<boolean>();

    readonly integrationsRoute = INTEGRATIONS_ROUTE;

    readonly tokenConfigured = signal(false);

    /**
     * When the token stops working and whether the tracker still accepts it, announced as the forge
     * connections' list announces a connection's token: fourteen days ahead, then expired — and a refusal
     * first, since a refused token's date no longer matters.
     */
    readonly tokenState = signal<TicketTokenState | null>(null);

    // Why reading each stored state failed, or null when it was read. A failed read used to fall
    // back to "none stored", which tells an operator whose token is in place that it is missing —
    // and invites a save over it.
    readonly tokenStateError = signal<string | null>(null);
    readonly ticketWebhookSecretStateError = signal<string | null>(null);
    readonly webhookSecretStateError = signal<string | null>(null);
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
            next: (state) => {
                this.savingToken.set(false);
                this.tokenConfigured.set(state.configured);
                this.tokenState.set(state);
                this.tokenStateError.set(null);
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
                this.ticketWebhookSecretStateError.set(null);
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
                this.webhookSecretStateError.set(null);
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

    /** Where the token's known expiry stands now, by the forge connections' rule and window. */
    tokenExpiry(): ExpiryState {
        return expiryState(this.tokenState()?.expiresAt, new Date());
    }

    tokenDaysLeft(): number {
        const expiresAt = this.tokenState()?.expiresAt;
        return expiresAt ? daysLeft(expiresAt, new Date()) : 0;
    }

    getWebhookUrl(provider: string): string {
        return `${window.location.origin}/api/v1/tickets/webhook/${provider}`;
    }

    copyWebhookUrl(provider: string): void {
        const url = this.getWebhookUrl(provider);
        void navigator.clipboard.writeText(url).then(() => {
            this.webhookCopied.set(provider);
            setTimeout(() => this.webhookCopied.set(null), 3000);
        });
    }

    private load(): void {
        const unread = (response: unknown) => messageOf(response, this.i18n.t('settings.secret_state_failed'));

        this.settingsApi.ticketTokenState().subscribe({
            next: (state) => {
                this.tokenConfigured.set(state.configured);
                this.tokenState.set(state);
                this.tokenStateError.set(null);
            },
            error: (response) => {
                this.tokenConfigured.set(false);
                this.tokenState.set(null);
                this.tokenStateError.set(unread(response));
            }
        });

        this.settingsApi.webhookSecretState().subscribe({
            next: ({ configured }) => {
                this.webhookSecretConfigured.set(configured);
                this.webhookSecretStateError.set(null);
            },
            error: (response) => {
                this.webhookSecretConfigured.set(false);
                this.webhookSecretStateError.set(unread(response));
            }
        });

        this.settingsApi.ticketWebhookSecretState().subscribe({
            next: ({ configured }) => {
                this.ticketWebhookSecretConfigured.set(configured);
                this.ticketWebhookSecretStateError.set(null);
            },
            error: (response) => {
                this.ticketWebhookSecretConfigured.set(false);
                this.ticketWebhookSecretStateError.set(unread(response));
            }
        });
    }
}
