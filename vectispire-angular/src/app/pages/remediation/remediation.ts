import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal, ChangeDetectionStrategy } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { MessageModule } from '@openng/optimus-ui/message';
import { TagModule } from '@openng/optimus-ui/tag';
import { TargetsApi } from '@/app/core/api/targets.api';
import { RemediationApi } from '@/app/core/api/remediation.api';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { TranslatePipe } from '@/app/core/i18n/translate.pipe';
import { SelectModule } from '@openng/optimus-ui/select';
import { FormsModule } from '@angular/forms';
import type {
    HighImpactFix,
    MonitoredContainer,
    MonitoredRepository,
    RemediationCoverage,
    SecurityDebtReport
} from '@/app/core/api.models';
import { LatestRequest } from '@/app/core/latest-request';

/**
 * What to do, in order — and not what is wrong.
 *
 * <p><b>The calculation existed, the screen did not.</b> {@code /api/v1/remediation/high-impact-fixes}
 * ranks upgrades by what they close against what they cost, and {@code getHighImpactFixes} sat
 * waiting in the front-end service with no component calling it. The product could therefore answer
 * "where do I start" and told nobody: the dashboard showed an extract of it in a card, among eight
 * others.
 *
 * <p><b>One action per row, and not one vulnerability per row.</b> That is the difference from the
 * list of findings. Fourteen findings from the same library across six repositories are not
 * fourteen decisions: they are one version bump. The list of findings answers "what is wrong", this
 * one answers "what do I do on Monday morning", and a team with only the first sorts noise instead
 * of reducing risk.
 *
 * <p><b>The debt is at the top because it gives the scale.</b> A work order with no total reads
 * like an infinite list; knowing that the first ten rows close half the estate is what makes people
 * start.
 */
@Component({
    selector: 'app-remediation',
    standalone: true,
    imports: [
        CommonModule,
        RouterLink,
        FormsModule,
        ButtonModule,
        MessageModule,
        SelectModule,
        TagModule,
        TranslatePipe
    ],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './remediation.html'
})
export class Remediation {
    private readonly fixesRequest = new LatestRequest();
    private readonly debtRequest = new LatestRequest();
    private readonly coverageRequest = new LatestRequest();

    private readonly targetsApi = inject(TargetsApi);
    private readonly remediationApi = inject(RemediationApi);
    private readonly i18n = inject(I18nService);

    readonly fixes = signal<HighImpactFix[]>([]);
    readonly debt = signal<SecurityDebtReport | null>(null);

    /**
     * The plan's admission: what a version bump will not close.
     *
     * <p><b>Because a user read a failure where there was a correct calculation.</b> A repository
     * whose backlog is made of exposed secrets shows a single action against hundreds of open
     * findings — which is accurate, the ranking keeps only vulnerabilities carrying a package, and
     * nothing on the screen said so. A wrong number gets corrected; mistrust is kept.
     */
    readonly coverage = signal<RemediationCoverage | null>(null);
    readonly loading = signal(true);
    readonly error = signal<string | null>(null);
    readonly expanded = signal<string | null>(null);

    /**
     * The target the plan covers, or the whole estate.
     *
     * <p>A single dropdown for repositories and images: the question is "what am I responsible for
     * on Monday", and it is not asked differently depending on whether one ships a repository or an
     * image. The value carries its kind so the call knows which parameter to set.
     */
    readonly targets = signal<{ label: string; value: string }[]>([]);
    scope = '';

    /**
     * How many rows are asked for.
     *
     * <p><b>Ten by default, and not "everything".</b> A short work order is what makes people
     * start; that is also why this grows in steps instead of offering pagination — nobody wants
     * page 4 of a remediation plan, one wants to know what comes after the first ten.
     */
    readonly wanted = signal(10);
    readonly CEILING = 50;

    /** True as long as the server returned as many as were asked for: there may be more. */
    readonly mayHaveMore = computed(() => this.wanted() < this.CEILING && this.fixes().length >= this.wanted());

    /**
     * What the rows shown close, added up.
     *
     * <p>One CVE can appear under two packages; this total therefore counts findings and not
     * distinct vulnerabilities, and the label says so.
     */
    readonly closedByTheList = computed(() => this.fixes().reduce((sum, fix) => sum + fix.cveCountResolved, 0));

    readonly hoursOfTheList = computed(
        () => Math.round(this.fixes().reduce((sum, fix) => sum + fix.estimatedHours, 0) * 10) / 10
    );

    constructor() {
        this.load();

        // The targets are loaded separately: being unable to list them does not prevent reading the
        // whole estate's plan, which is what the page shows by default.
        this.targetsApi.repositories().subscribe({
            next: (repositories: MonitoredRepository[]) =>
                this.addTargets(
                    repositories.map((repository) => ({
                        label: repository.name ?? repository.url,
                        value: `repo:${repository.id}`
                    }))
                ),
            error: () => {}
        });
        this.targetsApi.containers().subscribe({
            next: (containers: MonitoredContainer[]) =>
                this.addTargets(
                    containers.map((container) => ({
                        label: `${container.imageName}:${container.tag}`,
                        value: `container:${container.id}`
                    }))
                ),
            error: () => {}
        });
    }

    private addTargets(more: { label: string; value: string }[]): void {
        this.targets.update((current) => [...current, ...more]);
    }

    /** Reloads the plan for the scope and size asked for. */
    load(): void {
        this.loading.set(true);
        this.error.set(null);

        const [kind, id] = this.scope ? this.scope.split(':') : [null, null];
        const repoId = kind === 'repo' ? Number(id) : undefined;
        const containerId = kind === 'container' ? Number(id) : undefined;

        this.fixesRequest.run(this.remediationApi.getHighImpactFixes(repoId, containerId, this.wanted()), {
            next: (fixes) => {
                this.fixes.set(fixes);
                this.loading.set(false);
            },
            error: () => {
                this.error.set(this.i18n.t('remediation.plan_failed'));
                this.loading.set(false);
            }
        });

        // Separately: an unavailable debt figure must not erase a work order that did arrive. It is
        // the page's context, not its subject.
        this.debtRequest.run(this.remediationApi.getSecurityDebt(repoId, containerId), {
            next: (debt) => this.debt.set(debt),
            error: () => {}
        });

        // And the admission likewise: not knowing what the plan leaves out beats not seeing the
        // plan. Reset first, so that one scope does not keep the other's admission.
        this.coverage.set(null);
        this.coverageRequest.run(this.remediationApi.getRemediationCoverage(repoId, containerId), {
            next: (coverage) => this.coverage.set(coverage),
            error: () => {}
        });
    }

    /** Changes target: the size asked for goes back to ten, the plan no longer being the same. */
    changeScope(): void {
        this.wanted.set(10);
        this.expanded.set(null);
        this.load();
    }

    showMore(): void {
        this.wanted.update((current) => Math.min(current * 2 + 5, this.CEILING));
        this.load();
    }

    toggle(fix: HighImpactFix): void {
        this.expanded.set(this.expanded() === fix.packageName ? null : fix.packageName);
    }

    isExpanded(fix: HighImpactFix): boolean {
        return this.expanded() === fix.packageName;
    }

    /**
     * The severity that governs the row, for the tint.
     *
     * <p>A single critical decides the colour: it is what decides the urgency, and an average would
     * have diluted it in the count.
     */
    severityOf(fix: HighImpactFix): 'danger' | 'warn' | 'info' {
        if (fix.criticalCveCount > 0) return 'danger';
        if (fix.highCveCount > 0) return 'warn';
        return 'info';
    }
}
