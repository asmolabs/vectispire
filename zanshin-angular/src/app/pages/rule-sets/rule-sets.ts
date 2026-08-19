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
import type { RuleSetImpact, RuleSetSummary } from '../../core/api.models';

/**
 * Uploading Semgrep rule sets, and choosing which one is active.
 *
 * Zanshin bundles one rule — the public sets are not redistributable — so coverage arrives
 * from here. The alternative, `ZANSHIN_SEMGREP_RULES_DIR`, is read by the process that
 * scans: every remote agent needs the directory on its own filesystem, and nothing checks
 * that it has it. An uploaded set travels on the task, so every executor scans with the
 * same rules.
 *
 * **The impact panel is the point of this screen, not the upload button.** A rule id enters
 * an issue's fingerprint: activating a set whose rules differ makes the next scan stop
 * finding the ones that disappeared, which resolves their open issues along with the triage
 * decisions, justifications and review dates attached to them. Nothing errors, and the
 * dashboard looks *better* afterwards. So activation is a second, separate step, and the
 * cost is spelled out before the button appears.
 *
 * The files are read in the browser and posted as JSON. No archive is sent, so there is no
 * archive to extract server-side and no path traversal to defend against.
 */
@Component({
    selector: 'app-rule-sets',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, CardModule, InputTextModule, MessageModule, TableModule, TagModule],
    template: `
        <div class="mb-4">
            <h1 class="text-2xl font-semibold m-0">Semgrep rule sets</h1>
            <p class="text-muted-color mt-1 mb-0">
                Zanshin ships one rule; the public sets are not redistributable, so source-code coverage comes from a set you
                install here. What you upload travels with every scan, including to remote agents.
            </p>
        </div>

        @if (error(); as message) {
            <p-message severity="error" [closable]="true" styleClass="mb-4 w-full">{{ message }}</p-message>
        }
        @if (notice(); as message) {
            <p-message severity="success" [closable]="true" styleClass="mb-4 w-full">{{ message }}</p-message>
        }

        <p-card styleClass="mb-4">
            <ng-template #title>Upload a set</ng-template>

            <div class="flex flex-col gap-4">
                <div class="flex flex-col gap-2">
                    <label for="rule-set-name" class="font-medium">Name</label>
                    <input pInputText id="rule-set-name" [(ngModel)]="name" placeholder="opengrep-rules v1.0.0" />
                </div>

                <div class="flex flex-col gap-2">
                    <label for="rule-set-files" class="font-medium">Rule files</label>
                    <input
                        id="rule-set-files"
                        type="file"
                        multiple
                        accept=".yaml,.yml"
                        (change)="pick($event)"
                        class="text-sm"
                    />
                    <small class="text-muted-color">
                        YAML only. Selecting a folder works in most browsers. Nothing is sent until you upload.
                    </small>
                </div>

                @if (picked().length > 0) {
                    <p class="m-0 text-sm">{{ picked().length }} file(s) selected.</p>
                }

                <div>
                    <p-button
                        label="Upload"
                        icon="pi pi-upload"
                        [loading]="uploading()"
                        [disabled]="picked().length === 0 || !name.trim()"
                        (onClick)="upload()"
                    />
                </div>
            </div>
        </p-card>

        <p-card>
            <ng-template #title>Stored sets</ng-template>

            <p-table [value]="sets()" dataKey="id" styleClass="p-datatable-sm">
                <ng-template #header>
                    <tr>
                        <th>Name</th>
                        <th class="text-right">Rules</th>
                        <th class="text-right">Files</th>
                        <th>Uploaded</th>
                        <th>State</th>
                        <th></th>
                    </tr>
                </ng-template>

                <ng-template #body let-set>
                    <tr>
                        <td>
                            <div class="font-medium">{{ set.name }}</div>
                            <div class="text-muted-color text-xs font-mono">{{ set.contentHash.slice(0, 12) }}</div>
                        </td>
                        <td class="text-right">{{ set.ruleCount }}</td>
                        <td class="text-right">{{ set.fileCount }}</td>
                        <td>
                            <div>{{ set.uploadedAt | date: 'short' }}</div>
                            <div class="text-muted-color text-xs">{{ set.uploadedBy ?? '—' }}</div>
                        </td>
                        <td>
                            @if (set.isActive) {
                                <p-tag severity="success" value="Active" />
                            } @else {
                                <p-tag severity="secondary" value="Stored" />
                            }
                        </td>
                        <td class="text-right">
                            @if (!set.isActive) {
                                <p-button label="Review activation" size="small" [text]="true" (onClick)="review(set)" />
                            }
                        </td>
                    </tr>
                </ng-template>

                <ng-template #emptymessage>
                    <tr>
                        <td colspan="6" class="text-muted-color">
                            Nothing uploaded. Scans use the single bundled rule, plus ZANSHIN_SEMGREP_RULES_DIR where it is set.
                        </td>
                    </tr>
                </ng-template>
            </p-table>

            @if (active()) {
                <div class="mt-4">
                    <p-button label="Deactivate, back to the bundled rule" severity="secondary" [text]="true" (onClick)="deactivate()" />
                </div>
            }
        </p-card>

        <!--
            The confirmation. Shown only once the impact is known, never before: the whole
            reason this screen has two steps is that the number below is invisible in the
            data and permanent in its effect.
        -->
        @if (candidate(); as set) {
            @if (impact(); as cost) {
                <p-card styleClass="mt-4">
                    <ng-template #title>Activate "{{ set.name }}"?</ng-template>

                    <div class="flex flex-col gap-4">
                        <div class="flex gap-8">
                            <div>
                                <div class="text-muted-color text-sm">Rules added</div>
                                <div class="text-xl font-semibold">{{ cost.addedRules }}</div>
                            </div>
                            <div>
                                <div class="text-muted-color text-sm">Rules removed</div>
                                <div class="text-xl font-semibold">{{ cost.removedRules }}</div>
                            </div>
                        </div>

                        @if (cost.affectedIssues > 0) {
                            <p-message severity="warn" [closable]="false" styleClass="w-full">
                                <div>
                                    <p class="m-0 font-medium">
                                        {{ cost.affectedIssues }} open issue(s) will be resolved by the next scan.
                                    </p>
                                    <p class="m-0 mt-2 text-sm">
                                        Their rules are not in this set, so the scanner will stop finding them. Their triage
                                        decisions — justifications, review dates, who decided — go with them, and this cannot be
                                        undone by re-uploading the old set: the issues come back as new.
                                    </p>
                                    <p class="m-0 mt-2 text-sm">
                                        Rules losing issues: <span class="font-mono">{{ cost.losingIssues.slice(0, 10).join(', ') }}</span>
                                        @if (cost.losingIssues.length > 10) {
                                            <span> and {{ cost.losingIssues.length - 10 }} more.</span>
                                        }
                                    </p>
                                </div>
                            </p-message>
                        } @else {
                            <p-message severity="info" [closable]="false" styleClass="w-full">
                                No open issue depends on a rule this set drops. Nothing in the backlog is lost.
                            </p-message>
                        }

                        <div class="flex gap-2">
                            <p-button label="Activate" icon="pi pi-check" [loading]="activating()" (onClick)="activate(set, cost)" />
                            <p-button label="Cancel" severity="secondary" [text]="true" (onClick)="candidate.set(null)" />
                        </div>
                    </div>
                </p-card>
            }
        }
    `
})
export class RuleSets {
    private readonly api = inject(ApiService);

    readonly sets = signal<RuleSetSummary[]>([]);
    readonly picked = signal<{ name: string; content: string }[]>([]);
    readonly candidate = signal<RuleSetSummary | null>(null);
    readonly impact = signal<RuleSetImpact | null>(null);
    readonly uploading = signal(false);
    readonly activating = signal(false);
    readonly error = signal<string | null>(null);
    readonly notice = signal<string | null>(null);

    name = '';

    constructor() {
        this.reload();
    }

    active(): boolean {
        return this.sets().some((set) => set.isActive);
    }

    /**
     * Reads the chosen files in the browser.
     *
     * Read here rather than posted as multipart so the request carries JSON: no archive
     * reaches the server, hence no extraction and no path traversal to guard against.
     */
    async pick(event: Event): Promise<void> {
        const input = event.target as HTMLInputElement;
        const files = Array.from(input.files ?? []);
        this.error.set(null);

        try {
            this.picked.set(await Promise.all(files.map(async (file) => ({ name: file.name, content: await file.text() }))));
        } catch {
            this.picked.set([]);
            this.error.set('One of the selected files could not be read.');
        }
    }

    upload(): void {
        this.uploading.set(true);
        this.error.set(null);
        this.notice.set(null);

        this.api.uploadRuleSet(this.name.trim(), this.picked()).subscribe({
            next: (stored) => {
                this.uploading.set(false);
                this.picked.set([]);
                this.name = '';
                // Stored, not active. Saying so is the point: an operator who assumed the
                // upload took effect would wait for coverage that is not there.
                this.notice.set(`Stored ${stored.fileCount} files, ${stored.ruleCount} rules. Review activation to put it in use.`);
                this.reload();
            },
            error: (response) => {
                this.uploading.set(false);
                this.error.set(response?.error?.message ?? 'The upload was refused.');
            }
        });
    }

    review(set: RuleSetSummary): void {
        this.candidate.set(set);
        this.impact.set(null);
        this.api.ruleSetImpact(set.id).subscribe({
            next: (cost) => this.impact.set(cost),
            error: () => {
                this.candidate.set(null);
                this.error.set('The impact of this activation could not be computed; it has not been activated.');
            }
        });
    }

    activate(set: RuleSetSummary, cost: RuleSetImpact): void {
        this.activating.set(true);
        // The warning the operator had in front of them travels with the activation and is
        // kept on the row: "why did four hundred issues close that afternoon" stays
        // answerable months later.
        const note = `${cost.addedRules} rules added, ${cost.removedRules} removed, ${cost.affectedIssues} open issues affected.`;

        this.api.activateRuleSet(set.id, note).subscribe({
            next: () => {
                this.activating.set(false);
                this.candidate.set(null);
                this.notice.set(`"${set.name}" is active. It ships with every scan from now on.`);
                this.reload();
            },
            error: (response) => {
                this.activating.set(false);
                this.error.set(response?.error?.message ?? 'The activation failed.');
            }
        });
    }

    deactivate(): void {
        this.api.deactivateRuleSets().subscribe({
            next: () => {
                this.notice.set('Back to the bundled rule. Scans will find less from the next run on.');
                this.reload();
            },
            error: () => this.error.set('The deactivation failed.')
        });
    }

    private reload(): void {
        this.api.ruleSets().subscribe({
            next: (response) => this.sets.set(response.ruleSets),
            error: () => this.error.set('The stored rule sets could not be loaded.')
        });
    }
}
