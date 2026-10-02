import { DatePipe } from '@angular/common';
import { Component, inject, signal, ChangeDetectionStrategy } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Observable } from 'rxjs';
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
import { LatestRequest } from '../../core/latest-request';
import type { CataloguePreview, RuleSetImpact, RuleSetLosesIssuesProblem, RuleSetSummary } from '../../core/api.models';

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

/** A change of active set under review: activating a stored set, or returning to the bundled rules. */
export type RuleSetChange = { kind: 'activate'; set: RuleSetSummary } | { kind: 'deactivate' };

const LOSES_ISSUES = 'urn:vectispire:problem:rule-set-activation-loses-issues';

/** The refusal's members when it is the "this change loses issues" one, `null` for any other. */
function losesIssues(failure: unknown): RuleSetLosesIssuesProblem | null {
    const body = (failure as { error?: unknown } | null)?.error;
    if (!body || typeof body !== 'object') return null;
    const problem = body as Partial<RuleSetLosesIssuesProblem>;
    return problem.type === LOSES_ISSUES && typeof problem.affectedIssues === 'number'
        ? (problem as RuleSetLosesIssuesProblem)
        : null;
}

@Component({
    selector: 'app-rule-sets',
    imports: [
        DatePipe,
        FormsModule,
        ButtonModule,
        CardModule,
        CheckboxModule,
        InputTextModule,
        MessageModule,
        TableModule,
        TagModule,
        RuleCoverageBanner,
        TranslatePipe
    ],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './rule-sets.html'
})
export class RuleSets {
    private readonly ruleSetsApi = inject(RuleSetsApi);
    private readonly i18n = inject(I18nService);

    readonly sets = signal<RuleSetSummary[]>([]);
    readonly picked = signal<{ name: string; content: string }[]>([]);

    /** How many files in the selection were not YAML. Shown, never merely dropped. */
    readonly ignored = signal(0);
    readonly change = signal<RuleSetChange | null>(null);
    readonly impact = signal<RuleSetImpact | null>(null);
    /**
     * Set when the server refused the confirmation because the count moved since the preview: the
     * panel then shows the server's number, and the next click accepts that one — never retried
     * on the operator's behalf, since the whole point is that they read it.
     */
    readonly backlogChanged = signal(false);
    private readonly preview = new LatestRequest();
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
        this.ruleSetsApi.fetchRuleCatalogue(preview.commit, [...this.chosen()], preview.licence_sha256).subscribe({
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
            this.picked.set(
                await Promise.all(yaml.map(async (file) => ({ name: file.name, content: await file.text() })))
            );
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
                this.notice.set(
                    this.i18n.t('rule_sets.uploaded_notice', { files: stored.fileCount, rules: stored.ruleCount })
                );
                this.reload();
            },
            error: (response) => {
                this.uploading.set(false);
                this.error.set(messageOf(response, this.i18n.t('rule_sets.error_upload')));
            }
        });
    }

    review(set: RuleSetSummary): void {
        this.open({ kind: 'activate', set }, this.ruleSetsApi.ruleSetImpact(set.id), () =>
            this.i18n.t('rule_sets.error_impact')
        );
    }

    /** Returning to the bundled rules drops the active set's rules, so it is previewed the same way. */
    reviewDeactivation(): void {
        this.open({ kind: 'deactivate' }, this.ruleSetsApi.deactivationImpact(), () =>
            this.i18n.t('rule_sets.error_deactivate_impact')
        );
    }

    cancel(): void {
        this.preview.cancel();
        this.change.set(null);
        this.impact.set(null);
        this.backlogChanged.set(false);
    }

    private open(change: RuleSetChange, cost: Observable<RuleSetImpact>, failure: () => string): void {
        this.change.set(change);
        this.impact.set(null);
        this.backlogChanged.set(false);
        this.error.set(null);
        this.preview.run(cost, {
            next: (impact) => this.impact.set(impact),
            error: () => {
                this.change.set(null);
                this.error.set(failure());
            }
        });
    }

    /**
     * Carries out the reviewed change, stating the loss the operator saw.
     *
     * **`acceptLosing` is the number on the screen, not a flag.** The server re-reads the count
     * in the transaction that activates and refuses unless they are equal, so a preview taken
     * before new findings arrived authorises the loss it displayed and no more. Omitted at zero:
     * a change that loses nothing needs no acceptance.
     */
    confirm(change: RuleSetChange, cost: RuleSetImpact): void {
        this.activating.set(true);
        this.error.set(null);
        const acceptLosing = cost.affectedIssues > 0 ? cost.affectedIssues : undefined;
        const request: Observable<unknown> =
            change.kind === 'activate'
                ? // The warning the operator had in front of them travels with the activation and
                  // is kept on the row: "why did four hundred issues close that afternoon" stays
                  // answerable months later.
                  this.ruleSetsApi.activateRuleSet(
                      change.set.id,
                      `${cost.addedRules} rules added, ${cost.removedRules} removed, ${cost.affectedIssues} open issues affected.`,
                      acceptLosing
                  )
                : this.ruleSetsApi.deactivateRuleSets(acceptLosing);

        request.subscribe({
            next: () => {
                this.activating.set(false);
                this.cancel();
                this.notice.set(
                    change.kind === 'activate'
                        ? this.i18n.t('rule_sets.activated_notice', { name: change.set.name })
                        : this.i18n.t('rule_sets.deactivated_notice')
                );
                this.reload();
            },
            error: (response: unknown) => {
                this.activating.set(false);
                const moved = losesIssues(response);
                if (moved) {
                    // The server's count replaces the preview's, rules included, and the panel
                    // stays open for a second confirmation with that number.
                    this.impact.set({
                        ...cost,
                        affectedIssues: moved.affectedIssues,
                        losingIssues: moved.losingIssues ?? []
                    });
                    this.backlogChanged.set(true);
                    return;
                }
                this.error.set(
                    messageOf(
                        response,
                        change.kind === 'activate'
                            ? this.i18n.t('rule_sets.error_activate')
                            : this.i18n.t('rule_sets.error_deactivate')
                    )
                );
            }
        });
    }

    private reload(): void {
        this.ruleSetsApi.ruleSets().subscribe({
            next: (response) => this.sets.set(response.ruleSets),
            error: () => this.error.set(this.i18n.t('rule_sets.error_load'))
        });
    }
}
