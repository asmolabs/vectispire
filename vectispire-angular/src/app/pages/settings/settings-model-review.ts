import { CommonModule } from '@angular/common';
import { Component, DestroyRef, computed, inject, signal, ChangeDetectionStrategy } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { messageOf } from '../../core/api-error';
import { SettingsApi } from '../../core/api/settings.api';
import type { OllamaCheck } from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { SettingsState } from './settings-state';

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
    return (
        /^10\./.test(host) ||
        /^192\.168\./.test(host) ||
        /^172\.(1[6-9]|2\d|3[01])\./.test(host) ||
        /^f[cd][0-9a-f]{2}:/.test(host)
    );
}

/**
 * The top of the model review card: where the code goes, who accepted that, whether the model
 * answers, and the provider's API key.
 *
 * <p>Rendered inside the catalogue's card rather than as a card of its own, because every line of
 * it is about the settings listed underneath — so it is created when the AI tab shows that card,
 * and its key state is read then.
 */
@Component({
    selector: 'app-settings-model-review',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, InputTextModule, MessageModule, TranslatePipe],
    templateUrl: './settings-model-review.html',
    changeDetection: ChangeDetectionStrategy.Eager,
    host: { class: 'contents' }
})
export class SettingsModelReview {
    private readonly settingsApi = inject(SettingsApi);
    private readonly i18n = inject(I18nService);
    readonly state = inject(SettingsState);

    readonly openAiKeyConfigured = signal(false);
    readonly savingOpenAiKey = signal(false);
    openAiKeyInput = '';

    readonly ollama = signal<OllamaCheck | null>(null);
    readonly testingOllama = signal(false);

    /**
     * Whether the current configuration permits the code to leave the estate.
     *
     * <p>Two conditions, not one: the acknowledgement is what opens the guard, and the endpoint is
     * what it opens onto. Either alone is not a leak — an acknowledged setting pointing at
     * localhost sends nothing, and OpenAI's address without the acknowledgement is refused before
     * the request is made.
     */
    readonly aiSendsCodeOffSite = computed(() => {
        const values = this.state.values();
        if (values['ai_review_allow_remote_url'] !== 'true') {
            return false;
        }
        const url =
            this.state.aiProvider() === 'openai'
                ? (values['ai_review_openai_url'] ?? '')
                : (values['ai_review_ollama_url'] ?? '');
        return !isLocalEndpoint(url);
    });

    /** Who accepted the data-leak risk, and when — empty strings when nobody has. */
    readonly riskAcknowledgedBy = computed(() => this.state.values()['ai_review_risk_acknowledged_by'] ?? '');
    readonly riskAcknowledgedAt = computed(() => this.state.values()['ai_review_risk_acknowledged_at'] ?? '');

    constructor() {
        this.state.register(() => this.load(), inject(DestroyRef));
    }

    testOllama(): void {
        this.testingOllama.set(true);
        this.ollama.set(null);
        this.settingsApi.testOllama().subscribe({
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
                    detail: this.i18n.t('settings.error_connection_test_not_run'),
                    provider: this.state.aiProvider(),
                    // The check never ran, so it learned nothing about the destination. The banner
                    // above is driven by the form's own values, not by this.
                    remoteAllowed: false
                });
            }
        });
    }

    saveOpenAiKey(): void {
        this.savingOpenAiKey.set(true);
        this.state.error.set(null);
        this.settingsApi.setOpenAiKey(this.openAiKeyInput).subscribe({
            next: ({ configured }) => {
                this.savingOpenAiKey.set(false);
                this.openAiKeyConfigured.set(configured);
                // Cleared from the model at the same time as from the field, like the tracker
                // token: keeping it would leave the key reachable in the open tab.
                this.openAiKeyInput = '';
                this.state.saved.set(true);
            },
            error: (response) => {
                this.savingOpenAiKey.set(false);
                this.state.error.set(messageOf(response, this.i18n.t('settings.error_save_api_key')));
            }
        });
    }

    private load(): void {
        this.settingsApi.openAiKeyState().subscribe({
            next: ({ configured }) => this.openAiKeyConfigured.set(configured),
            error: () => this.openAiKeyConfigured.set(false)
        });
    }
}
