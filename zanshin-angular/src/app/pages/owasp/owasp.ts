import { CommonModule } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { TagModule } from '@openng/optimus-ui/tag';
import { ApiService } from '../../core/api.service';
import { saveDocument } from '../../core/download';
import type { MonitoredRepository, OwaspReport } from '../../core/api.models';

/**
 * The OWASP Top 10 posture report, written by the configured model.
 *
 * **Repositories only.** Half the Top 10 describes an application and the decisions behind it —
 * access control, insecure design, logging. A container image has an inventory and a base
 * distribution, and a report filing its CVEs under "Broken Access Control" would have the right
 * headings and nothing behind them.
 *
 * **On a button, never on a scan.** A model call takes tens of seconds and answers slightly
 * differently each time; hanging it off every scan would make the queue unpredictable and fill
 * the table with reports nobody read.
 */
@Component({
    selector: 'app-owasp',
    standalone: true,
    imports: [CommonModule, FormsModule, CardModule, ButtonModule, MessageModule, SelectModule, TagModule],
    template: `
        <div class="mb-4">
            <h1 class="text-2xl font-semibold m-0">OWASP report</h1>
            <p class="text-muted-color mt-1 mb-0">
                A Top 10 (2021) posture report written by the configured model, from what the scanners found.
            </p>
        </div>

        <p-card styleClass="mb-4">
            <div class="flex flex-col sm:flex-row sm:flex-wrap gap-3 sm:items-end">
                <div class="flex flex-col gap-1">
                    <label for="repo" class="text-sm text-muted-color">Repository</label>
                    <p-select
                        inputId="repo"
                        [options]="repositories()"
                        [(ngModel)]="selected"
                        optionLabel="displayName"
                        optionValue="id"
                        placeholder="Pick a repository"
                        (onChange)="loadLatest()"
                        styleClass="w-full"
                        class="w-full sm:min-w-[24rem]" />
                </div>
                <p-button
                    label="Run the analysis"
                    icon="pi pi-sparkles"
                    [disabled]="selected === null"
                    [loading]="running()"
                    (onClick)="run()" />
            </div>
            <p class="text-sm text-muted-color mt-3 mb-0">
                <!-- Said on the screen, not only in the code: an operator deciding whether to turn this
                      on needs to know what leaves the machine. -->
                The findings are sent to the model — their identifiers, severities and file paths.
                <span class="font-medium">The source code is not.</span>
                The report is a document: nothing in it becomes an issue, and nothing in it reaches a gate.
            </p>
        </p-card>

        @if (error(); as message) {
            <p-message severity="error" [closable]="false" styleClass="mb-4 w-full">{{ message }}</p-message>
        }

        @if (running()) {
            <p-message severity="info" [closable]="false" styleClass="mb-4 w-full">
                The model is writing. A local model takes tens of seconds on a backlog of this size.
            </p-message>
        }

        @if (report(); as current) {
            <p-card>
                <ng-template #title>
                    Report
                    @if (current.status === 'failed') {
                        <p-tag value="failed" severity="danger" />
                    }
                </ng-template>
                <ng-template #subtitle>
                    <div class="flex flex-wrap items-center justify-between gap-3">
                        <span class="text-muted-color text-sm">
                            {{ current.model }} · scan #{{ current.scanId }} ·
                            {{ current.createdAt | date: 'dd/MM/yyyy HH:mm' }}
                        </span>
                        @if (current.status === 'completed') {
                            <!-- Only for a report that exists. A PDF of "the model could not be
                                  reached" would look like a report and say nothing, and a file
                                  travels away from the screen that explained it. -->
                            <p-button label="Export PDF" icon="pi pi-file-pdf" severity="secondary" size="small"
                                      (onClick)="downloadPdf()" />
                        }
                    </div>
                </ng-template>

                @if (current.status === 'failed') {
                    <!-- The attempt is kept and shown. A run that vanished would leave this page
                          identical to one nobody ever asked for. -->
                    <p-message severity="error" [closable]="false" styleClass="w-full">
                        {{ current.error }}
                    </p-message>
                } @else {
                    <!--
                        Rendered from the blocks the server parsed, never from the Markdown.
                        Every branch places text into an element with interpolation, so nothing
                        here interprets markup — which matters because this prose is written by a
                        model fed with findings whose descriptions come from the audited
                        repository. Assigning it as inner HTML, with a Markdown library or
                        without, would be an injection path with three authors and no owner.
                    -->
                    <div class="owasp-report">
                        @for (block of current.blocks; track $index) {
                            @switch (block.kind) {
                                @case ('CATEGORY') {
                                    <h2 class="text-lg font-semibold mt-5 mb-2 px-3 py-2 rounded"
                                        style="background: var(--surface-100); color: var(--primary-color)">
                                        {{ block.text }}
                                    </h2>
                                }
                                @case ('HEADING') {
                                    <h3 class="font-semibold mt-5 mb-2 pb-1"
                                        [class.text-lg]="block.level <= 2"
                                        [style.border-bottom]="block.level <= 2 ? '1px solid var(--surface-border)' : null">
                                        {{ block.text }}
                                    </h3>
                                }
                                @case ('BULLET') {
                                    <div class="flex gap-2 mb-1">
                                        <span style="color: var(--primary-color)">•</span>
                                        <span>{{ block.text }}</span>
                                    </div>
                                }
                                @case ('NUMBERED') {
                                    <div class="flex gap-2 mb-1">
                                        <span class="font-semibold" style="color: var(--primary-color)">
                                            {{ block.marker }}.
                                        </span>
                                        <span>{{ block.text }}</span>
                                    </div>
                                }
                                @default {
                                    <p class="my-2 leading-relaxed">{{ block.text }}</p>
                                }
                            }
                        } @empty {
                            <p class="text-muted-color m-0">The model returned an empty report.</p>
                        }
                    </div>
                }
            </p-card>
        } @else if (selected !== null && !running() && !error()) {
            <p-card>
                <p class="text-muted-color m-0">
                    No report yet for this repository. Run the analysis to produce one.
                </p>
            </p-card>
        }
    `
})
export class Owasp {
    private readonly api = inject(ApiService);

    selected: number | null = null;

    readonly repositories = signal<MonitoredRepository[]>([]);
    readonly report = signal<OwaspReport | null>(null);
    readonly running = signal(false);
    readonly error = signal<string | null>(null);

    constructor() {
        this.api.repositories().subscribe({
            next: (rows) => this.repositories.set(rows),
            error: () => this.error.set('The repositories could not be loaded.')
        });
    }

    loadLatest(): void {
        this.report.set(null);
        this.error.set(null);
        if (this.selected === null) {
            return;
        }
        this.api.owaspReport(this.selected).subscribe({
            next: (report) => this.report.set(report),
            // A 404 here means "none yet", which is a state and not a failure.
            error: () => this.report.set(null)
        });
    }

    downloadPdf(): void {
        const id = this.selected;
        if (id === null) {
            return;
        }
        // Through HttpClient, never a navigation: the token is in memory and only the
        // interceptor puts it on a request. A navigation carries none, and the browser saves the
        // 401's empty body as a zero-byte file.
        this.api.downloadDocument(`/api/v1/repositories/${id}/owasp-review/export.pdf`).subscribe({
            next: (response) => saveDocument(response, `zanshin-owasp-${id}.pdf`),
            error: () => this.error.set('The PDF could not be produced.')
        });
    }

    run(): void {
        if (this.selected === null) {
            return;
        }
        this.running.set(true);
        this.error.set(null);

        this.api.runOwaspReport(this.selected).subscribe({
            next: (report) => {
                this.report.set(report);
                this.running.set(false);
            },
            error: (response) => {
                this.running.set(false);
                this.error.set(response?.error?.message ?? 'The report could not be produced.');
            }
        });
    }
}
