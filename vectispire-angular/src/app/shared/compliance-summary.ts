import { NgClass } from '@angular/common';
import { ChangeDetectionStrategy, Component, computed, inject, input, output, signal } from '@angular/core';
import { ButtonModule } from '@openng/optimus-ui/button';
import { TagModule } from '@openng/optimus-ui/tag';
import { TranslatePipe } from '../core/i18n/translate.pipe';
import { I18nService } from '../core/i18n/i18n.service';
import type { ComplianceEvaluation, ComplianceStatus, ComplianceSummary } from '../core/api.models';

/**
 * A verdict in words. Literal keys, so that the i18n check sees every one of them (decision 0019):
 * the tags used to show the wire value, and `NO_DATA` reached the reader as a constant.
 */
const STATUS_KEYS = {
    COMPLIANT: 'soa.measured.COMPLIANT',
    PARTIAL: 'soa.measured.PARTIAL',
    NON_COMPLIANT: 'soa.measured.NON_COMPLIANT',
    NO_DATA: 'soa.measured.NO_DATA'
} as const satisfies Record<ComplianceStatus, string>;

/**
 * A `ComplianceSummary`, drawn: the executive figures, the per-target matrix, the frameworks and the
 * controls of the one selected.
 *
 * **One drawing for every scope.** The estate, a project and a solution receive the same shape from
 * the server — a scope's summary is the estate's computed over the scope's targets — and a second
 * copy of this template would be a second answer to "how does a verdict read", which would drift
 * from the first on the first change, `NO_DATA` first of all.
 */
@Component({
    selector: 'app-compliance-summary',
    imports: [NgClass, ButtonModule, TagModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './compliance-summary.html'
})
export class ComplianceSummaryView {
    private readonly i18n = inject(I18nService);

    readonly summary = input.required<ComplianceSummary>();
    /** The per-target matrix: the estate's global view and a scope's page show it, one target does not. */
    readonly showMatrix = input(true);
    /** Whether each matrix row offers to narrow the page to its target — only where the page can. */
    readonly inspectable = input(false);
    readonly inspect = output<string>();

    readonly Math = Math;
    readonly selectedFramework = signal<string>('NIS_2');

    /**
     * The share of the scope observed inside the freshness window.
     *
     * **A hundred per cent on an empty scope, deliberately.** Zero would read as an alarm where there
     * is nothing to observe, and an alarm that fires on a fresh deployment teaches its reader to
     * ignore the one that matters.
     */
    readonly freshnessRate = computed(() => {
        const data = this.summary();
        if (data.totalMonitoredTargets === 0) {
            return 100;
        }
        return Math.round((data.freshTargets / data.totalMonitoredTargets) * 100);
    });

    /**
     * Targets for which no observation exists — not "stale", **absent**.
     *
     * A stale observation is dated: you know what you do not know. A target never scanned presents
     * no known vulnerability, which makes it green on any table that counts findings. This is the
     * figure that separates "clean" from "never looked at".
     */
    readonly neverObserved = computed(() => {
        const data = this.summary();
        return Math.max(0, data.totalMonitoredTargets - data.observedTargets);
    });

    /** Red as soon as one target has never been observed; orange below three quarters of the scope. */
    readonly freshnessTone = computed(() => {
        if (this.neverObserved() > 0) {
            return 'text-red-500';
        }
        return this.freshnessRate() < 75 ? 'text-orange-500' : 'text-green-500';
    });

    readonly frameworks = computed(() => {
        this.i18n.translations();
        return [
            {
                key: 'NIS_2',
                label: this.i18n.t('compliance.frameworks.nis2'),
                desc: this.i18n.t('compliance.frameworks.nis2_desc')
            },
            {
                key: 'ISO_27001',
                label: this.i18n.t('compliance.frameworks.iso27001'),
                desc: this.i18n.t('compliance.frameworks.iso27001_desc')
            },
            {
                key: 'EU_CRA',
                label: this.i18n.t('compliance.frameworks.eu_cra'),
                desc: this.i18n.t('compliance.frameworks.eu_cra_desc')
            },
            {
                key: 'DORA',
                label: this.i18n.t('compliance.frameworks.dora'),
                desc: this.i18n.t('compliance.frameworks.dora_desc')
            },
            {
                key: 'PCI_DSS',
                label: this.i18n.t('compliance.frameworks.pci_dss'),
                desc: this.i18n.t('compliance.frameworks.pci_dss_desc')
            },
            {
                key: 'SOC_2',
                label: this.i18n.t('compliance.frameworks.soc2'),
                desc: this.i18n.t('compliance.frameworks.soc2_desc')
            }
        ];
    });

    frameworkLabel(key: string): string {
        return this.frameworks().find((f) => f.key === key)?.label ?? key.replace('_', ' ');
    }

    frameworkDesc(key: string): string {
        return this.frameworks().find((f) => f.key === key)?.desc ?? key;
    }

    readonly orderedEvaluations = computed<ComplianceEvaluation[]>(() => {
        const desiredOrder = ['NIS_2', 'ISO_27001', 'EU_CRA', 'DORA', 'PCI_DSS', 'SOC_2'];
        const orderMap = new Map(desiredOrder.map((key, i) => [key, i]));
        return [...this.summary().evaluations].sort((a, b) => {
            const orderA = orderMap.get(a.framework) ?? 99;
            const orderB = orderMap.get(b.framework) ?? 99;
            return orderA - orderB;
        });
    });

    readonly activeEvaluation = computed<ComplianceEvaluation | null>(
        () => this.summary().evaluations.find((e) => e.framework === this.selectedFramework()) ?? null
    );

    selectFramework(key: string): void {
        this.selectedFramework.set(key);
    }

    /** The verdict in the reader's language; a status the client does not know yet is shown as sent. */
    statusLabel(status: string): string {
        this.i18n.translations();
        const key = (STATUS_KEYS as Record<string, string | undefined>)[status];
        return key ? this.i18n.t(key) : status;
    }

    statusSeverity(status: string): 'success' | 'warn' | 'danger' | 'secondary' {
        if (status === 'COMPLIANT') return 'success';
        if (status === 'PARTIAL') return 'warn';
        // No data is no verdict: neither green nor red.
        if (status === 'NO_DATA') return 'secondary';
        return 'danger';
    }

    /** A score, or a dash where nothing was measured — its zero is no measurement. */
    scoreOf(status: string, score: number): string {
        return status === 'NO_DATA' ? '—' : score + '%';
    }

    gateStatusSeverity(status: string): 'success' | 'info' | 'warn' | 'danger' {
        if (status === 'PASSED') return 'success';
        if (status === 'SCANNING' || status === 'IN_PROGRESS') return 'info';
        if (status === 'NEVER_SCANNED') return 'warn';
        return 'danger';
    }
}
