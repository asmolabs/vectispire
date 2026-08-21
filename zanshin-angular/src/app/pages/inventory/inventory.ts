import { CommonModule } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { ApiService } from '../../core/api.service';
import type { InventoryOccurrence } from '../../core/api.models';

/**
 * "Do we ship this library, and in which release of ours?"
 *
 * **Not a filter over the backlog.** An issue exists only where something is wrong, so the
 * backlog is silent on exactly the component being asked about on the day a vulnerability is
 * published and no scanner knows it yet. This searches the inventory — every component a scan
 * catalogued, flagged or not.
 *
 * The project version travels beside the component version, and the two are labelled apart:
 * confusing them is the one mistake that makes the answer useless.
 */
@Component({
    selector: 'app-inventory',
    standalone: true,
    imports: [CommonModule, FormsModule, CardModule, TableModule, TagModule, MessageModule, ButtonModule, InputTextModule],
    template: `
        <div class="mb-4">
            <h1 class="text-2xl font-semibold m-0">Component search</h1>
            <p class="text-muted-color mt-1 mb-0">
                Which of our projects ship a library, in which version — and in which release of ours.
            </p>
        </div>

        <p-card styleClass="mb-4">
            <div class="flex flex-col sm:flex-row sm:flex-wrap gap-3 sm:items-end">
                <div class="flex flex-col gap-1">
                    <label for="name" class="text-sm text-muted-color">Library</label>
                    <input
                        pInputText
                        id="name"
                        [(ngModel)]="name"
                        (keyup.enter)="search()"
                        placeholder="log4j-core, or org.apache.logging"
                        class="w-full sm:min-w-[22rem]" />
                </div>
                <div class="flex flex-col gap-1">
                    <label for="version" class="text-sm text-muted-color">Version (exact, optional)</label>
                    <input pInputText id="version" [(ngModel)]="version" (keyup.enter)="search()" placeholder="2.14.1" />
                </div>
                <p-button label="Search" icon="pi pi-search" (onClick)="search()" [loading]="loading()" />
            </div>
            <p class="text-sm text-muted-color mt-3 mb-0">
                The name matches loosely, on the component or its package URL. The version, when given, matches
                exactly — <span class="font-medium">2.14.1</span> is not <span class="font-medium">2.14.10</span>.
            </p>
        </p-card>

        @if (error(); as message) {
            <p-message severity="error" [closable]="false" styleClass="mb-4 w-full">{{ message }}</p-message>
        }

        @if (searched()) {
            <p-card>
                <ng-template #title>
                    {{ occurrences().length }} occurrence{{ occurrences().length === 1 ? '' : 's' }}
                </ng-template>

                @if (truncated()) {
                    <!-- Said rather than left to be inferred from a full page: a capped list read
                          as complete is a wrong answer to "is that all of them". -->
                    <p-message severity="warn" [closable]="false" styleClass="mb-3 w-full">
                        More occurrences than can be shown — narrow the search by version.
                    </p-message>
                }

                <p-table
                    [value]="occurrences()"
                    dataKey="scanId"
                    styleClass="p-datatable-sm"
                    [paginator]="occurrences().length > 25"
                    [rows]="25"
                    [rowsPerPageOptions]="[25, 50, 100]">
                    <ng-template #header>
                        <tr>
                            <th>Library</th>
                            <th style="width: 9rem">Version</th>
                            <th style="width: 8rem">Origin</th>
                            <th>Project</th>
                            <th style="width: 10rem">Project version</th>
                            <th style="width: 11rem">Scanned</th>
                        </tr>
                    </ng-template>
                    <ng-template #body let-row>
                        <tr>
                            <td>
                                <div class="font-medium">{{ row.component }}</div>
                                @if (row.purl) {
                                    <div class="text-sm text-muted-color">{{ row.purl }}</div>
                                }
                            </td>
                            <td>{{ row.componentVersion ?? '—' }}</td>
                            <td>
                                @if (row.direct === true) {
                                    <p-tag value="direct" severity="warn" />
                                } @else if (row.direct === false) {
                                    <p-tag value="transitive" severity="secondary" />
                                } @else {
                                    <!-- Not "transitive": some ecosystems ship no dependency graph,
                                          and a default would state something nothing established. -->
                                    <span class="text-muted-color text-sm">unknown</span>
                                }
                            </td>
                            <td>{{ row.targetName }} <span class="text-muted-color text-sm">· {{ row.branch }}</span></td>
                            <td>
                                @if (row.projectVersion) {
                                    <span class="font-medium">{{ row.projectVersion }}</span>
                                } @else {
                                    <span class="text-muted-color">unknown</span>
                                }
                            </td>
                            <td>{{ row.scannedAt | date: 'dd/MM/yyyy HH:mm' }}</td>
                        </tr>
                    </ng-template>
                    <ng-template #emptymessage>
                        <tr>
                            <td colspan="6" class="text-muted-color">
                                No scan has catalogued this component. That is not "we do not use it": a target
                                never scanned since the inventory existed has none.
                            </td>
                        </tr>
                    </ng-template>
                </p-table>
            </p-card>
        }
    `
})
export class Inventory {
    private readonly api = inject(ApiService);

    name = '';
    version = '';

    readonly occurrences = signal<InventoryOccurrence[]>([]);
    readonly truncated = signal(false);
    readonly loading = signal(false);
    readonly searched = signal(false);
    readonly error = signal<string | null>(null);

    search(): void {
        if (!this.name.trim()) {
            return;
        }
        this.loading.set(true);
        this.error.set(null);

        this.api.searchComponents(this.name.trim(), this.version.trim()).subscribe({
            next: (results) => {
                this.occurrences.set(results.occurrences);
                this.truncated.set(results.truncated);
                this.searched.set(true);
                this.loading.set(false);
            },
            error: () => {
                this.loading.set(false);
                this.error.set('The search could not be run.');
            }
        });
    }
}
