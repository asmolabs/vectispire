import { CommonModule } from '@angular/common';
import { ChangeDetectionStrategy, Component, effect, inject, input, signal } from '@angular/core';
import { MessageModule } from '@openng/optimus-ui/message';
import { messageOf } from '../core/api-error';
import { ReportImportsApi } from '../core/api/report-imports.api';
import type { CoverageImport, TestReportImport } from '../core/api.models';
import { I18nService } from '../core/i18n/i18n.service';
import { TranslatePipe } from '../core/i18n/translate.pipe';
import { LatestRequest } from '../core/latest-request';

/**
 * A repository's latest coverage report and latest test report (decision 0032 §7), as its declared
 * sources deposited them.
 *
 * **Figures, not findings.** Neither opens an issue nor reaches a gate: a checklist reads them. What
 * this shows is what the report counted and where it came from — the format, the source, the commit
 * and branch the pipeline *stated* (verified against nothing, and labelled as such) — so a figure can
 * be traced to the run that produced it. The server keeps fifty of each; the latest is the one a
 * reader asks about, and the first the server answers, newest first.
 *
 * Read-only, like the SARIF history beside it: the uploads come from CI with a declared key. A 404
 * reads as "not visible to you", which confirms nothing.
 */
@Component({
    selector: 'app-report-imports',
    standalone: true,
    imports: [CommonModule, MessageModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    template: `
        <p class="text-sm text-muted-color mt-0">{{ 'report_imports.explain' | translate }}</p>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <section class="border border-surface rounded-border p-3" data-testid="latest-coverage">
                <h3 class="text-base font-semibold mt-0 mb-2">{{ 'report_imports.coverage_title' | translate }}</h3>
                @if (coverageError(); as message) {
                    <p-message severity="warn" [closable]="false" styleClass="w-full">{{ message }}</p-message>
                } @else if (coverageLoading()) {
                    <p class="text-sm text-muted-color m-0">{{ 'common.loading' | translate }}</p>
                } @else if (coverage(); as report) {
                    <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm m-0">
                        <dt class="text-muted-color">{{ 'report_imports.lines' | translate }}</dt>
                        <dd class="m-0 font-medium" data-testid="coverage-lines">
                            {{ ratio(report.linesCovered, report.linesTotal) }}
                        </dd>
                        <dt class="text-muted-color">{{ 'report_imports.branches' | translate }}</dt>
                        <dd class="m-0" data-testid="coverage-branches">
                            @if (report.branchesCovered !== null && report.branchesTotal) {
                                {{ ratio(report.branchesCovered, report.branchesTotal) }}
                            } @else {
                                <span class="text-muted-color">{{ 'report_imports.no_branches' | translate }}</span>
                            }
                        </dd>
                        <dt class="text-muted-color">{{ 'report_imports.format' | translate }}</dt>
                        <dd class="m-0 font-mono">
                            {{ report.format }}
                            @if (report.toolVersion) {
                                <span class="text-muted-color">{{ report.toolVersion }}</span>
                            }
                        </dd>
                        <dt class="text-muted-color">{{ 'report_imports.commit' | translate }}</dt>
                        <dd class="m-0 font-mono break-all">{{ report.commit ?? '—' }}</dd>
                        <dt class="text-muted-color">{{ 'report_imports.branch' | translate }}</dt>
                        <dd class="m-0 font-mono">{{ report.branch ?? '—' }}</dd>
                        <dt class="text-muted-color">{{ 'report_imports.imported_at' | translate }}</dt>
                        <dd class="m-0">{{ report.importedAt | date: 'dd/MM/yyyy HH:mm' }}</dd>
                        <dt class="text-muted-color">{{ 'report_imports.source' | translate }}</dt>
                        <dd class="m-0 font-mono">{{ report.sourceSlug }}</dd>
                    </dl>
                    <p class="text-xs text-muted-color mb-0 mt-2">{{ 'report_imports.stated' | translate }}</p>
                } @else {
                    <p class="text-sm text-muted-color m-0" data-testid="no-coverage">
                        {{ 'report_imports.no_coverage' | translate }}
                    </p>
                }
            </section>

            <section class="border border-surface rounded-border p-3" data-testid="latest-test-report">
                <h3 class="text-base font-semibold mt-0 mb-2">{{ 'report_imports.tests_title' | translate }}</h3>
                @if (testsError(); as message) {
                    <p-message severity="warn" [closable]="false" styleClass="w-full">{{ message }}</p-message>
                } @else if (testsLoading()) {
                    <p class="text-sm text-muted-color m-0">{{ 'common.loading' | translate }}</p>
                } @else if (testReport(); as report) {
                    <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm m-0">
                        <dt class="text-muted-color">{{ 'report_imports.tests' | translate }}</dt>
                        <dd class="m-0 font-medium" data-testid="tests-count">{{ report.testsCount }}</dd>
                        <dt class="text-muted-color">{{ 'report_imports.failures' | translate }}</dt>
                        <dd class="m-0" data-testid="failures-count" [class.text-red-600]="report.failuresCount > 0">
                            {{ report.failuresCount }}
                        </dd>
                        <dt class="text-muted-color">{{ 'report_imports.errors' | translate }}</dt>
                        <dd class="m-0" data-testid="errors-count" [class.text-red-600]="report.errorsCount > 0">
                            {{ report.errorsCount }}
                        </dd>
                        <dt class="text-muted-color">{{ 'report_imports.skipped' | translate }}</dt>
                        <dd class="m-0" data-testid="skipped-count">{{ report.skippedCount }}</dd>
                        <dt class="text-muted-color">{{ 'report_imports.format' | translate }}</dt>
                        <dd class="m-0 font-mono">{{ report.format }}</dd>
                        <dt class="text-muted-color">{{ 'report_imports.imported_at' | translate }}</dt>
                        <dd class="m-0">{{ report.importedAt | date: 'dd/MM/yyyy HH:mm' }}</dd>
                        <dt class="text-muted-color">{{ 'report_imports.source' | translate }}</dt>
                        <dd class="m-0 font-mono">{{ report.sourceSlug }}</dd>
                    </dl>
                } @else {
                    <p class="text-sm text-muted-color m-0" data-testid="no-test-report">
                        {{ 'report_imports.no_tests' | translate }}
                    </p>
                }
            </section>
        </div>
    `
})
export class ReportImports {
    private readonly api = inject(ReportImportsApi);
    private readonly i18n = inject(I18nService);
    // Two streams, two slots: cancelling the coverage request must not cancel the test report's.
    private readonly coverageRequest = new LatestRequest();
    private readonly testsRequest = new LatestRequest();

    readonly repositoryId = input.required<number>();

    readonly coverage = signal<CoverageImport | null>(null);
    readonly coverageLoading = signal(true);
    readonly coverageError = signal<string | null>(null);

    readonly testReport = signal<TestReportImport | null>(null);
    readonly testsLoading = signal(true);
    readonly testsError = signal<string | null>(null);

    constructor() {
        // Follows the input, and the latest request wins: another repository opened while the first
        // answer is on its way must not show the first one's figures.
        effect(() => this.load(this.repositoryId()));
    }

    /** "83.3 % (250 / 300)", in the reader's language; a total of zero has no percentage. */
    ratio(covered: number, total: number): string {
        if (total <= 0) return '—';
        const percent = new Intl.NumberFormat(this.i18n.currentLang(), { maximumFractionDigits: 1 }).format(
            (covered / total) * 100
        );
        return this.i18n.t('report_imports.ratio', { percent, covered, total });
    }

    private load(repositoryId: number): void {
        this.coverage.set(null);
        this.coverageError.set(null);
        this.coverageLoading.set(true);
        this.coverageRequest.run(this.api.coverageImports(repositoryId), {
            next: (imports) => {
                this.coverage.set(imports[0] ?? null);
                this.coverageLoading.set(false);
            },
            error: (failure) => {
                this.coverageLoading.set(false);
                this.coverageError.set(this.failureOf(failure));
            }
        });

        this.testReport.set(null);
        this.testsError.set(null);
        this.testsLoading.set(true);
        this.testsRequest.run(this.api.testReportImports(repositoryId), {
            next: (imports) => {
                this.testReport.set(imports[0] ?? null);
                this.testsLoading.set(false);
            },
            error: (failure) => {
                this.testsLoading.set(false);
                this.testsError.set(this.failureOf(failure));
            }
        });
    }

    private failureOf(failure: unknown): string {
        return (failure as { status?: number } | null)?.status === 404
            ? this.i18n.t('sarif_imports.not_visible')
            : messageOf(failure, this.i18n.t('report_imports.error_load'));
    }
}
