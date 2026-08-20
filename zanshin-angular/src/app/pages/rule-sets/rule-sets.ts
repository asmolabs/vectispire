import { CommonModule } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { CheckboxModule } from '@openng/optimus-ui/checkbox';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { messageOf } from '../../core/api-error';
import { ApiService } from '../../core/api.service';
import type { CataloguePreview, RuleSetImpact, RuleSetSummary } from '../../core/api.models';

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
    imports: [CommonModule, FormsModule, ButtonModule, CardModule, CheckboxModule, InputTextModule, MessageModule, TableModule, TagModule],
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

        <p-card styleClass="mb-4">
            <ng-template #title>Fetch from the upstream catalogue</ng-template>

            <!--
                **Zanshin does not ship these rules, it fetches them on your instruction.** That
                distinction is what makes this legitimate: they travel from their author to this
                installation because somebody here asked. Decision 0006 has the full argument.
            -->
            <div class="flex flex-col gap-4">
                <div>
                    <p-button label="Read the catalogue" icon="pi pi-download" [loading]="loadingCatalogue()"
                              (onClick)="readCatalogue()" />
                </div>
                <small class="text-muted-color max-w-3xl">
                    Clones the upstream and shows what it holds right now. <strong>It publishes no tags</strong>, so
                    what is pinned is the commit — and the rules you fetch are frozen in the database from that moment,
                    which is what keeps later scans reproducible.
                </small>

                @if (catalogueError(); as message) {
                    <p-message severity="error" [closable]="false" styleClass="w-full">{{ message }}</p-message>
                }

                @if (catalogue(); as preview) {
                    <div class="border-t pt-4" style="border-color: var(--surface-border)">
                        <p class="m-0 mb-3 text-sm">
                            <span class="font-medium">{{ preview.upstream }}</span> at commit
                            <span class="font-mono">{{ preview.commit.slice(0, 12) }}</span>.
                        </p>

                        <div class="font-medium mb-2">Languages</div>
                        <div class="flex flex-wrap gap-3 mb-4">
                            @for (language of languagesOf(preview); track language.name) {
                                <div class="flex items-center gap-2">
                                    <p-checkbox [inputId]="'lang-' + language.name" [binary]="true"
                                                [ngModel]="chosen().has(language.name)"
                                                (ngModelChange)="choose(language.name, $event)" />
                                    <label [for]="'lang-' + language.name" class="cursor-pointer text-sm">
                                        {{ language.name }}
                                        <span class="text-muted-color">({{ language.count }})</span>
                                    </label>
                                </div>
                            }
                        </div>

                        <!--
                            Taking everything is the highest-risk option, so it is not the default
                            and it is not one click. A rule id enters an issue fingerprint, so the
                            larger the set the more triage a later tag bump can destroy — and a
                            gate that fires on noise is switched off within a week.
                        -->
                        <p-message severity="warn" [closable]="false" styleClass="w-full mb-4">
                            Choose the languages you actually scan. Every rule id becomes part of an issue's identity,
                            so a set you do not need is triage you can lose the next time the upstream moves a file.
                        </p-message>

                        <div class="font-medium mb-2">{{ preview.licenceName }}</div>
                        <pre class="text-xs p-3 border rounded overflow-auto max-h-64 whitespace-pre-wrap"
                             style="border-color: var(--surface-border)">{{ preview.licence }}</pre>

                        <div class="flex items-start gap-2 mt-3">
                            <p-checkbox inputId="licence-accepted" [binary]="true" [(ngModel)]="licenceAccepted" />
                            <label for="licence-accepted" class="cursor-pointer text-sm">
                                I accept these terms on behalf of this installation.
                                <span class="block text-muted-color">
                                    The Commons Clause takes whoever adopts these rules out of open source in the OSI
                                    sense. Building an agent image that contains them is a legitimate use;
                                    <strong>publishing that image is redistribution</strong>. Your acceptance is
                                    recorded in the audit log with the tag, the commit and a digest of this text.
                                </span>
                            </label>
                        </div>

                        <div class="mt-4">
                            <p-button label="Fetch as a rule set" icon="pi pi-check" [loading]="fetching()"
                                      [disabled]="!licenceAccepted || chosen().size === 0" (onClick)="fetchCatalogue()" />
                            <span class="text-muted-color text-sm ml-3">Stored, not activated.</span>
                        </div>
                    </div>
                }
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
    /** The upstream catalogue: what came back, and what was chosen from it. */
    licenceAccepted = false;
    readonly catalogue = signal<CataloguePreview | null>(null);
    readonly catalogueError = signal<string | null>(null);
    readonly loadingCatalogue = signal(false);
    readonly fetching = signal(false);
    readonly chosen = signal<Set<string>>(new Set());

    languagesOf(preview: CataloguePreview): { name: string; count: number }[] {
        return Object.entries(preview.languages).map(([name, count]) => ({ name, count }));
    }

    choose(language: string, selected: boolean): void {
        const next = new Set(this.chosen());
        selected ? next.add(language) : next.delete(language);
        this.chosen.set(next);
    }

    readCatalogue(): void {
        this.loadingCatalogue.set(true);
        this.catalogueError.set(null);
        // Cleared, not kept: the acceptance is bound to one licence text, and leaving a tick
        // from a previous tag would carry an agreement to terms nobody has read.
        this.licenceAccepted = false;
        this.catalogue.set(null);
        this.chosen.set(new Set());

        this.api.ruleCatalogue().subscribe({
            next: (preview) => {
                this.loadingCatalogue.set(false);
                this.catalogue.set(preview);
            },
            error: (response) => {
                this.loadingCatalogue.set(false);
                // The server names the cause — a branch instead of a tag, a tag that does not
                // exist upstream. A generic message would send somebody to the wrong place.
                this.catalogueError.set(messageOf(response, 'The catalogue could not be read.'));
            }
        });
    }

    fetchCatalogue(): void {
        const preview = this.catalogue();
        if (!preview) return;

        this.fetching.set(true);
        this.api
            .fetchRuleCatalogue(preview.commit, [...this.chosen()], preview.licence_sha256)
            .subscribe({
                next: (stored) => {
                    this.fetching.set(false);
                    this.catalogue.set(null);
                    this.licenceAccepted = false;
                    this.notice.set(
                        `Fetched ${stored.ruleCount} rules from ${preview.upstream} at ${preview.commit.slice(0, 12)}. ` +
                            'Stored, not active — review the activation cost before switching to it.'
                    );
                    this.reload();
                },
                error: (response) => {
                    this.fetching.set(false);
                    this.catalogueError.set(messageOf(response, 'The fetch failed.'));
                }
            });
    }

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
                this.error.set(messageOf(response, 'The upload was refused.'));
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
                this.error.set(messageOf(response, 'The activation failed.'));
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
