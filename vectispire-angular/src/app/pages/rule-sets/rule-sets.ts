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
import { RuleSetsApi } from '../../core/api/rule-sets.api';
import { I18nService } from '../../core/i18n/i18n.service';
import type { CataloguePreview, RuleSetImpact, RuleSetSummary } from '../../core/api.models';

/**
 * Uploading Semgrep rule sets, and choosing which one is active.
 *
 * Vectispire bundles one rule — the public sets are not redistributable — so coverage arrives
 * from here. The alternative, `VECTISPIRE_SEMGREP_RULES_DIR`, is read by the process that
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
import { TranslatePipe } from '../../core/i18n/translate.pipe';
import { RuleCoverageBanner } from '@/app/shared/rule-coverage-banner';

@Component({
    selector: 'app-rule-sets',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, CardModule, CheckboxModule, InputTextModule, MessageModule, TableModule, TagModule, RuleCoverageBanner, TranslatePipe],
    templateUrl: './rule-sets.html'
})
export class RuleSets {
    private readonly ruleSetsApi = inject(RuleSetsApi);
    private readonly i18n = inject(I18nService);

    readonly sets = signal<RuleSetSummary[]>([]);
    readonly picked = signal<{ name: string; content: string }[]>([]);

    /** How many files in the selection were not YAML. Shown, never merely dropped. */
    readonly ignored = signal(0);
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

    /**
     * The OWASP categories this catalogue covers, sorted by identifier.
     *
     * **What it answers.** The OWASP grid marks a category "not covered" when no installed rule
     * declares it. A grey square therefore said two very different things — the product cannot look
     * there, or nobody imported the rules that can — and nothing told them apart without importing
     * first, which is the reverse of the order an operator wants.
     */
    categoriesOf(preview: CataloguePreview): { id: string; count: number }[] {
        return Object.entries(preview.categories)
            .map(([id, count]) => ({ id, count }))
            .sort((a, b) => a.id.localeCompare(b.id));
    }

    choose(language: string, selected: boolean): void {
        const next = new Set(this.chosen());
        if (selected) {
            next.add(language);
        } else {
            next.delete(language);
        }
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

        this.ruleSetsApi.ruleCatalogue().subscribe({
            next: (preview) => {
                this.loadingCatalogue.set(false);
                this.catalogue.set(preview);
            },
            error: (response) => {
                this.loadingCatalogue.set(false);
                // The server names the cause — a branch instead of a tag, a tag that does not
                // exist upstream. A generic message would send somebody to the wrong place.
                this.catalogueError.set(messageOf(response, this.i18n.t('rule_sets.error_catalogue_read')));
            }
        });
    }

    fetchCatalogue(): void {
        const preview = this.catalogue();
        if (!preview) return;

        this.fetching.set(true);
        this.ruleSetsApi
            .fetchRuleCatalogue(preview.commit, [...this.chosen()], preview.licence_sha256)
            .subscribe({
                next: (stored) => {
                    this.fetching.set(false);
                    this.catalogue.set(null);
                    this.licenceAccepted = false;
                    this.notice.set(
                        this.i18n.t('rule_sets.fetched_notice', {
                            count: stored.ruleCount,
                            upstream: preview.upstream,
                            commit: preview.commit.slice(0, 12)
                        })
                    );
                    this.reload();
                },
                error: (response) => {
                    this.fetching.set(false);
                    this.catalogueError.set(messageOf(response, this.i18n.t('rule_sets.error_fetch')));
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

        // **Filtered here, and the count of what was dropped is shown.** The server refuses the
        // whole upload on the first non-YAML file, deliberately: forty files selected and
        // thirty-eight stored is coverage somebody believes they have and does not. That rule is
        // right for a hand-picked selection and makes a folder impossible — a rule repository
        // holds a README, a licence and a CI configuration, so the upload was refused before it
        // began. Dropping them here is not the same silence: the operator chose a directory, not
        // those files, and the number left out is on the screen.
        const yaml = files.filter((file) => /\.ya?ml$/i.test(file.name));
        this.ignored.set(files.length - yaml.length);

        try {
            this.picked.set(await Promise.all(yaml.map(async (file) => ({ name: file.name, content: await file.text() }))));
        } catch {
            this.picked.set([]);
            this.ignored.set(0);
            this.error.set(this.i18n.t('rule_sets.error_file_read'));
        }
    }

    upload(): void {
        this.uploading.set(true);
        this.error.set(null);
        this.notice.set(null);

        this.ruleSetsApi.uploadRuleSet(this.name.trim(), this.picked()).subscribe({
            next: (stored) => {
                this.uploading.set(false);
                this.picked.set([]);
                this.ignored.set(0);
                this.name = '';
                // Stored, not active. Saying so is the point: an operator who assumed the
                // upload took effect would wait for coverage that is not there.
                this.notice.set(this.i18n.t('rule_sets.uploaded_notice', { files: stored.fileCount, rules: stored.ruleCount }));
                this.reload();
            },
            error: (response) => {
                this.uploading.set(false);
                this.error.set(messageOf(response, this.i18n.t('rule_sets.error_upload')));
            }
        });
    }

    review(set: RuleSetSummary): void {
        this.candidate.set(set);
        this.impact.set(null);
        this.ruleSetsApi.ruleSetImpact(set.id).subscribe({
            next: (cost) => this.impact.set(cost),
            error: () => {
                this.candidate.set(null);
                this.error.set(this.i18n.t('rule_sets.error_impact'));
            }
        });
    }

    activate(set: RuleSetSummary, cost: RuleSetImpact): void {
        this.activating.set(true);
        // The warning the operator had in front of them travels with the activation and is
        // kept on the row: "why did four hundred issues close that afternoon" stays
        // answerable months later.
        const note = `${cost.addedRules} rules added, ${cost.removedRules} removed, ${cost.affectedIssues} open issues affected.`;

        this.ruleSetsApi.activateRuleSet(set.id, note).subscribe({
            next: () => {
                this.activating.set(false);
                this.candidate.set(null);
                this.notice.set(this.i18n.t('rule_sets.activated_notice', { name: set.name }));
                this.reload();
            },
            error: (response) => {
                this.activating.set(false);
                this.error.set(messageOf(response, this.i18n.t('rule_sets.error_activate')));
            }
        });
    }

    deactivate(): void {
        this.ruleSetsApi.deactivateRuleSets().subscribe({
            next: () => {
                this.notice.set(this.i18n.t('rule_sets.deactivated_notice'));
                this.reload();
            },
            error: () => this.error.set(this.i18n.t('rule_sets.error_deactivate'))
        });
    }

    private reload(): void {
        this.ruleSetsApi.ruleSets().subscribe({
            next: (response) => this.sets.set(response.ruleSets),
            error: () => this.error.set(this.i18n.t('rule_sets.error_load'))
        });
    }
}
