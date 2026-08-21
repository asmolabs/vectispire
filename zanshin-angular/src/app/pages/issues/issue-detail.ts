import { CommonModule } from '@angular/common';
import { Component, inject, input, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { CardModule } from '@openng/optimus-ui/card';
import { MessageModule } from '@openng/optimus-ui/message';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { ApiService } from '../../core/api.service';
import type { IssueDetail } from '../../core/api.models';

const SEVERITY_SEVERITY: Record<string, 'danger' | 'warn' | 'secondary'> = {
    critical: 'danger',
    high: 'danger',
    medium: 'warn',
    low: 'secondary',
    negligible: 'secondary',
    unknown: 'secondary'
};

const TRIAGE_LABELS: Record<string, string> = {
    under_review: 'Under review',
    not_affected: 'Not affected',
    affected: 'Affected',
    fixed: 'Fixed',
    accepted: 'Risk accepted',
    false_positive: 'False positive'
};

/**
 * One issue, with what a row in the backlog cannot carry.
 *
 * The list already sends every column of an issue; this page exists for the two things that need
 * a query of their own — **where it was seen**, scan by scan with the project version each one
 * read, and **what was decided**, every triage transition with its author and justification.
 *
 * Those two answer the questions a row provokes and cannot settle: "is this still there in the
 * release we shipped" and "why is this dismissed".
 */
@Component({
    selector: 'app-issue-detail',
    standalone: true,
    imports: [CommonModule, RouterLink, CardModule, TableModule, TagModule, MessageModule],
    template: `
        @if (issue(); as detail) {
            <div class="mb-4">
                <a routerLink="/issues" class="text-sm">← Issues</a>
                <h1 class="text-2xl font-semibold m-0 mt-1">
                    {{ detail.identifier ?? detail.type }}
                </h1>
                <p class="text-muted-color mt-1 mb-0">
                    {{ detail.targetName }} · {{ typeLabel(detail.type) }} ·
                    seen {{ detail.timesSeen }} time{{ detail.timesSeen === 1 ? '' : 's' }}
                </p>
            </div>

            <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                <p-card>
                    <div class="text-muted-color text-sm">Severity</div>
                    <div class="mt-2">
                        <p-tag [value]="detail.severity ?? 'unknown'" [severity]="severityOf(detail.severity)" />
                    </div>
                </p-card>
                <p-card>
                    <div class="text-muted-color text-sm">State</div>
                    <div class="mt-2"><p-tag [value]="detail.state"
                                             [severity]="detail.state === 'open' ? 'warn' : 'success'" /></div>
                </p-card>
                <p-card>
                    <div class="text-muted-color text-sm">Triage</div>
                    <div class="text-lg font-medium mt-1">{{ triageLabel(detail.triageStatus) }}</div>
                </p-card>
                <p-card>
                    <div class="text-muted-color text-sm">Fix</div>
                    <div class="mt-1">
                        @if (detail.fixVersions) {
                            <span class="font-medium">{{ detail.fixVersions }}</span>
                        } @else {
                            <!-- Not blank: "no published fix" is the case that needs a human
                                  decision, and an empty cell reads as missing data. -->
                            <span class="text-muted-color">none published</span>
                        }
                    </div>
                </p-card>
            </div>

            <p-card styleClass="mb-4">
                <ng-template #title>What it is</ng-template>
                @if (detail.description) {
                    <p class="mt-0">{{ detail.description }}</p>
                }
                <div class="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-2 text-sm">
                    @if (detail.packageName) {
                        <div><span class="text-muted-color">Component</span> ·
                            {{ detail.packageName }} {{ detail.packageVersion }}</div>
                    }
                    @if (detail.filePath) {
                        <div><span class="text-muted-color">Location</span> ·
                            {{ detail.filePath }}@if (detail.line) {:{{ detail.line }}}</div>
                    }
                    @if (detail.isDirectDependency !== null) {
                        <div><span class="text-muted-color">Dependency</span> ·
                            {{ detail.isDirectDependency ? 'declared by this project' : 'pulled in by something else' }}</div>
                    }
                    @if (detail.cvssScore) {
                        <div><span class="text-muted-color">CVSS</span> · {{ detail.cvssScore }}</div>
                    }
                    @if (detail.epssScore) {
                        <div><span class="text-muted-color">EPSS</span> · {{ detail.epssScore }}</div>
                    }
                    @if (detail.isKev) {
                        <div class="font-medium" style="color: var(--red-500)">Actively exploited (CISA KEV)</div>
                    }
                    <div><span class="text-muted-color">First seen</span> ·
                        {{ detail.firstSeenAt | date: 'dd/MM/yyyy HH:mm' }}</div>
                    <div><span class="text-muted-color">Last seen</span> ·
                        {{ detail.lastSeenAt | date: 'dd/MM/yyyy HH:mm' }}</div>
                </div>
                @if (detail.link) {
                    <p class="mb-0 mt-3 text-sm">
                        <a [href]="detail.link" target="_blank" rel="noopener noreferrer">{{ detail.link }}</a>
                    </p>
                }
            </p-card>

            <p-card styleClass="mb-4">
                <ng-template #title>Decisions</ng-template>
                @if (detail.decisions.length === 0) {
                    <!-- Said rather than left blank: "detected and never decided upon" is a finding
                          of the audit, not an empty section. -->
                    <p class="text-muted-color m-0">
                        No decision has been recorded for this issue. It stands as first detected.
                    </p>
                } @else {
                    @for (decision of detail.decisions; track decision.occurredAt) {
                        <div class="mb-3">
                            <div>
                                <span class="text-muted-color">
                                    {{ decision.occurredAt | date: 'dd/MM/yyyy HH:mm' }} —
                                </span>
                                {{ triageLabel(decision.fromStatus) }} → {{ triageLabel(decision.toStatus) }}
                                @if (decision.justification) {
                                    ({{ decision.justification }})
                                }
                                @if (decision.actor) {
                                    by {{ decision.actor }}
                                } @else {
                                    <!-- A lapse is not somebody's decision. -->
                                    <em>expired automatically</em>
                                }
                            </div>
                            @if (decision.comment) {
                                <div class="text-sm text-muted-color italic">“{{ decision.comment }}”</div>
                            }
                        </div>
                    }
                }
            </p-card>

            <p-card>
                <ng-template #title>
                    Seen by
                    <span class="text-muted-color font-normal text-sm">
                        — which scan, on which version of the project
                    </span>
                </ng-template>
                <p-table
                    [value]="detail.sightings"
                    dataKey="scanId"
                    styleClass="p-datatable-sm"
                    [paginator]="detail.sightings.length > 15"
                    [rows]="15">
                    <ng-template #header>
                        <tr>
                            <th style="width: 7rem">Scan</th>
                            <th style="width: 12rem">When</th>
                            <th style="width: 9rem">Branch</th>
                            <th style="width: 10rem">Project version</th>
                            <th style="width: 8rem">Severity</th>
                        </tr>
                    </ng-template>
                    <ng-template #body let-sighting>
                        <tr>
                            <td><a [routerLink]="['/scans', sighting.scanId]">#{{ sighting.scanId }}</a></td>
                            <td>{{ sighting.scannedAt | date: 'dd/MM/yyyy HH:mm' }}</td>
                            <td>{{ sighting.branch }}</td>
                            <td>
                                @if (sighting.version) {
                                    {{ sighting.version }}
                                } @else {
                                    <span class="text-muted-color">unknown</span>
                                }
                            </td>
                            <td>{{ sighting.severity ?? '—' }}</td>
                        </tr>
                    </ng-template>
                    <ng-template #emptymessage>
                        <tr>
                            <td colspan="5" class="text-muted-color">
                                No sighting recorded — the findings of the scans that saw it have been purged.
                            </td>
                        </tr>
                    </ng-template>
                </p-table>
            </p-card>
        } @else if (error(); as message) {
            <p-message severity="error" [closable]="false" styleClass="w-full">{{ message }}</p-message>
        }
    `
})
export class IssueDetailPage {
    private readonly api = inject(ApiService);

    readonly id = input.required<string>();
    readonly issue = signal<IssueDetail | null>(null);
    readonly error = signal<string | null>(null);

    constructor() {
        queueMicrotask(() => {
            this.api.issue(Number(this.id())).subscribe({
                next: (detail) => this.issue.set(detail),
                error: () => this.error.set('This issue could not be loaded.')
            });
        });
    }

    severityOf(severity: string | null): 'danger' | 'warn' | 'secondary' {
        return SEVERITY_SEVERITY[severity ?? 'unknown'] ?? 'secondary';
    }

    triageLabel(status: string | null): string {
        return status ? (TRIAGE_LABELS[status] ?? status) : '—';
    }

    typeLabel(type: string): string {
        return type === 'sast' ? 'Vulnerable code' : type;
    }
}
