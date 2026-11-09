import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputNumberModule } from '@openng/optimus-ui/inputnumber';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { messageOf } from '../../core/api-error';
import { AgentsApi } from '../../core/api/agents.api';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { AgentsPage, CONCURRENCY_BOUNDS, withinBounds } from './agents-page';

/**
 * An agent declared: name, description, how credentials reach it, its labels and its limit. A form:
 * the name and the limit are required, and the field a refusal is about says so and points at it. On
 * success the secret the agent authenticates with is shown once, by the page.
 */
@Component({
    selector: 'app-declare-agent-dialog',
    imports: [
        FormsModule,
        ButtonModule,
        DialogModule,
        InputNumberModule,
        InputTextModule,
        MessageModule,
        SelectModule,
        TranslatePipe
    ],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './declare-agent-dialog.html'
})
export class DeclareAgentDialog {
    private readonly i18n = inject(I18nService);
    private readonly agentsApi = inject(AgentsApi);
    protected readonly page = inject(AgentsPage);
    protected readonly bounds = CONCURRENCY_BOUNDS;

    /** Which field the error under the form is about, so that field alone is marked invalid. */
    readonly invalid = signal<'name' | 'concurrent' | null>(null);

    readonly credentials = computed(() => {
        this.i18n.translations();
        return [
            {
                label: this.i18n.t('agents.credentials_modes.local'),
                value: 'local',
                hint: this.i18n.t('agents.credentials_modes.local_hint')
            },
            {
                label: this.i18n.t('agents.credentials_modes.delegated'),
                value: 'delegated',
                hint: this.i18n.t('agents.credentials_modes.delegated_hint')
            }
        ];
    });

    readonly hint = computed(
        () => this.credentials().find((entry) => entry.value === this.page.formCredentialsMode())?.hint ?? ''
    );

    save(): void {
        const page = this.page;
        const name = page.formName().trim();
        const maxConcurrent = page.formMaxConcurrent();
        if (!name) {
            this.refuse('name', this.i18n.t('agents.error_name_required'));
            return;
        }
        if (!withinBounds(maxConcurrent)) {
            this.refuse('concurrent', this.i18n.t('agents.error_concurrency_range'));
            return;
        }
        page.saving.set(true);
        page.formError.set(null);
        this.invalid.set(null);
        this.agentsApi
            .createAgent({
                name,
                description: page.formDescription().trim() || undefined,
                credentials_mode: page.formCredentialsMode(),
                labels: page.formLabels().trim() || undefined,
                max_concurrent: maxConcurrent
            })
            .subscribe({
                next: ({ secret }) => {
                    page.saving.set(false);
                    page.formVisible.set(false);
                    page.issuedSecret.set(secret);
                    page.secretVisible.set(true);
                    page.reload();
                },
                error: (response) => {
                    page.saving.set(false);
                    page.formError.set(messageOf(response, this.i18n.t('agents.error_declare')));
                }
            });
    }

    private refuse(field: 'name' | 'concurrent', message: string): void {
        this.invalid.set(field);
        this.page.formError.set(message);
    }
}
