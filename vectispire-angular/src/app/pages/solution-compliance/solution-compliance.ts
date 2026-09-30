import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal, untracked } from '@angular/core';
import { RouterLink } from '@angular/router';
import { CardModule } from '@openng/optimus-ui/card';
import { MessageModule } from '@openng/optimus-ui/message';
import { messageOf } from '../../core/api-error';
import { SolutionsApi } from '../../core/api/solutions.api';
import type { ScopeCompliance } from '../../core/api.models';
import { I18nService } from '../../core/i18n/i18n.service';
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { LatestRequest } from '../../core/latest-request';
import { ScopeComplianceView } from '../../shared/scope-compliance';

/**
 * A solution's compliance and score, over the targets filed in its projects that the reader sees.
 * The drawing is the project page's and the estate's; only the scope differs.
 */
@Component({
    selector: 'app-solution-compliance',
    standalone: true,
    imports: [RouterLink, CardModule, MessageModule, TranslatePipe, ScopeComplianceView],
    changeDetection: ChangeDetectionStrategy.Eager,
    template: `
        <div class="mb-4 flex items-start justify-between gap-4">
            <div class="min-w-0">
                <h1 class="text-2xl font-semibold m-0" data-testid="solution-title">
                    {{ 'solution_compliance.title' | translate }}
                    @if (scope(); as loaded) {
                        <span class="text-muted-color font-normal">— {{ loaded.name }}</span>
                    }
                </h1>
                <p class="text-muted-color mt-1 mb-0">{{ 'solution_compliance.subtitle' | translate }}</p>
            </div>
            <a routerLink="/solutions" class="whitespace-nowrap text-sm">
                <i class="pi pi-arrow-left" aria-hidden="true"></i>
                {{ 'project.back' | translate }}
            </a>
        </div>
        @if (error(); as message) {
            <p-message severity="error" [closable]="false" styleClass="mb-4 w-full" data-testid="error">{{
                message
            }}</p-message>
        }
        @if (notFound()) {
            <p-card styleClass="mb-4">
                <p class="m-0" data-testid="not-found">{{ 'solution_compliance.not_found' | translate }}</p>
            </p-card>
        } @else if (scope(); as loaded) {
            <app-scope-compliance [scope]="loaded" />
        } @else if (!error()) {
            <p class="text-muted-color">{{ 'common.loading' | translate }}</p>
        }
    `
})
export class SolutionCompliance {
    private readonly api = inject(SolutionsApi);
    private readonly i18n = inject(I18nService);
    private readonly request = new LatestRequest();

    /** The route's `:solutionId`, bound by `withComponentInputBinding`. */
    readonly solutionId = input.required<string>();
    readonly id = computed(() => Number(this.solutionId()));

    readonly scope = signal<ScopeCompliance | null>(null);
    readonly notFound = signal(false);
    readonly error = signal<string | null>(null);

    constructor() {
        effect(() => {
            const id = this.id();
            untracked(() => this.load(id));
        });
    }

    private load(id: number): void {
        this.scope.set(null);
        this.notFound.set(false);
        this.error.set(null);
        this.request.run(this.api.solutionCompliance(id), {
            next: (scope) => this.scope.set(scope),
            error: (failure) => {
                // A solution that does not exist and one the reader sees nothing of: the same 404.
                if ((failure as { status?: number } | null)?.status === 404) {
                    this.notFound.set(true);
                    return;
                }
                this.error.set(messageOf(failure, this.i18n.t('solution_compliance.error_load')));
            }
        });
    }
}
