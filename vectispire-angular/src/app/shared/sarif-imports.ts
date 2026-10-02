import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, effect, inject, input, signal } from '@angular/core';
import { MessageModule } from '@openng/optimus-ui/message';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { messageOf } from '../core/api-error';
import { SarifApi } from '../core/api/sarif.api';
import type { SarifImport } from '../core/api.models';
import { I18nService } from '../core/i18n/i18n.service';
import { TranslatePipe } from '../core/i18n/translate.pipe';
import { LatestRequest } from '../core/latest-request';

/**
 * A repository's SARIF imports, newest first — the latest fifty the server keeps answering.
 *
 * **Read-only, and there is no upload here by design.** An import comes from a declared source's
 * integration key, from CI; a session is not a source and the server refuses one. What this shows
 * is the dated evidence behind every imported issue: which source sent it, which tools, the
 * document's SHA-256 — so a report can be matched to the pipeline run that produced it — and what
 * it did to the backlog.
 *
 * A 404 reads as "not visible to you", in the words the server uses for an absent repository: it
 * confirms nothing, and neither does this.
 */
@Component({
    selector: 'app-sarif-imports',
    imports: [DatePipe, MessageModule, TableModule, TagModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    template: `
        @if (error(); as message) {
            <p-message severity="warn" [closable]="false" styleClass="w-full">{{ message }}</p-message>
        } @else {
            <p class="text-sm text-muted-color mt-0">{{ 'sarif_imports.explain' | translate }}</p>
            <p-table [value]="imports()" [loading]="loading()" dataKey="id" styleClass="p-datatable-sm">
                <ng-template #header>
                    <tr>
                        <th>{{ 'sarif_imports.col_when' | translate }}</th>
                        <th>{{ 'sarif_imports.col_source' | translate }}</th>
                        <th>{{ 'sarif_imports.col_tools' | translate }}</th>
                        <th class="text-right">{{ 'sarif_imports.col_results' | translate }}</th>
                        <th class="text-right">{{ 'sarif_imports.col_created' | translate }}</th>
                        <th class="text-right">{{ 'sarif_imports.col_resolved' | translate }}</th>
                        <th class="text-right">{{ 'sarif_imports.col_reopened' | translate }}</th>
                        <th>{{ 'sarif_imports.col_document' | translate }}</th>
                    </tr>
                </ng-template>
                <ng-template #body let-row>
                    <tr data-testid="sarif-import">
                        <td class="text-sm whitespace-nowrap">
                            {{ row.importedAt | date: 'dd/MM/yyyy HH:mm' }}
                            <div class="text-muted-color">{{ row.importedBy ?? '—' }}</div>
                        </td>
                        <td class="font-mono text-sm">{{ row.sourceSlug }}</td>
                        <td>
                            <!-- One tag per tool, as the declared sources list them: a tool name may hold a comma. -->
                            <div class="flex flex-wrap gap-1" data-testid="sarif-import-tools">
                                @for (tool of row.tools; track $index) {
                                    <p-tag severity="secondary" [value]="tool" />
                                }
                            </div>
                        </td>
                        <td class="text-right">{{ row.resultsCount }}</td>
                        <td class="text-right">{{ row.createdCount }}</td>
                        <td class="text-right">{{ row.resolvedCount }}</td>
                        <td class="text-right">{{ row.reopenedCount }}</td>
                        <td class="font-mono text-xs break-all" [title]="row.documentSha256">
                            {{ row.documentSha256 }}
                        </td>
                    </tr>
                </ng-template>
                <ng-template #emptymessage>
                    <tr>
                        <td colspan="8" class="text-center text-muted-color py-4">
                            {{ 'sarif_imports.none' | translate }}
                        </td>
                    </tr>
                </ng-template>
            </p-table>
        }
    `
})
export class SarifImports {
    private readonly api = inject(SarifApi);
    private readonly i18n = inject(I18nService);
    private readonly request = new LatestRequest();

    readonly repositoryId = input.required<number>();
    readonly imports = signal<SarifImport[]>([]);
    readonly loading = signal(true);
    readonly error = signal<string | null>(null);

    constructor() {
        // Follows the input, and the latest request wins: opening another repository's history
        // while the first answer is on its way must not show the first one's imports.
        effect(() => this.load(this.repositoryId()));
    }

    private load(repositoryId: number): void {
        this.loading.set(true);
        this.error.set(null);
        this.imports.set([]);
        this.request.run(this.api.sarifImports(repositoryId), {
            next: (imports) => {
                this.imports.set(imports);
                this.loading.set(false);
            },
            error: (failure) => {
                this.loading.set(false);
                this.error.set(
                    (failure as { status?: number } | null)?.status === 404
                        ? this.i18n.t('sarif_imports.not_visible')
                        : messageOf(failure, this.i18n.t('sarif_imports.error_load'))
                );
            }
        });
    }
}
