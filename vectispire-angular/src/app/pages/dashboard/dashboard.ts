import { CommonModule } from '@angular/common';
import { I18nService } from '../../core/i18n/i18n.service';
import { Component, computed, inject, signal, ChangeDetectionStrategy } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { ChartModule } from '@openng/optimus-ui/chart';
import { MessageModule } from '@openng/optimus-ui/message';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { DashboardApi } from '../../core/api/dashboard.api';
import { RemediationApi } from '../../core/api/remediation.api';
import type { DashboardOverview, Trends, PostureTrendAnalytics, SecurityDebtReport } from '../../core/api.models';
import { LastScanTag } from '../../shared/last-scan';

/** The severities in descending order, with their colour. A fixed order, not derived from the
 *  data: otherwise two successive loads could present them differently. */
const SEVERITY_TILES = [
    { key: 'critical', severity: 'danger' as const },
    { key: 'high', severity: 'warn' as const },
    { key: 'medium', severity: 'secondary' as const },
    { key: 'low', severity: 'secondary' as const }
];

/** The windows offered. Days, because that is the unit the route clamps and the axis shows. */
const WINDOW_DAYS = [
    { key: 'window_30d', value: 30 },
    { key: 'window_90d', value: 90 },
    { key: 'window_1y', value: 365 }
];

/**
 * A colour from the theme, or the fallback.
 *
 * Chart.js paints onto a canvas, where `var(--p-primary-500)` is not a colour but an unparsable
 * string that silently renders as transparent. So the variable is resolved to its value here, and
 * a fallback is kept for the case where it resolves to nothing — a chart with invisible lines
 * looks exactly like a chart with no data.
 */
function themeColour(variable: string, fallback: string): string {
    if (typeof document === 'undefined') return fallback;
    const value = getComputedStyle(document.documentElement).getPropertyValue(variable).trim();
    return value || fallback;
}

import { TranslatePipe } from '../../core/i18n/translate.pipe';

@Component({
    selector: 'app-dashboard',
    standalone: true,
    imports: [CommonModule, RouterLink, ButtonModule, CardModule, ChartModule, MessageModule, TableModule, TagModule, LastScanTag, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './dashboard.html'
})
export class Dashboard {
    private readonly i18n = inject(I18nService);
    private readonly dashboardApi = inject(DashboardApi);
    private readonly remediationApi = inject(RemediationApi);
    readonly severities = computed(() => {
        this.i18n.translations();
        return SEVERITY_TILES.map((tile) => ({ ...tile, label: this.i18n.t(`severities.${tile.key}`) }));
    });
    readonly windows = computed(() => {
        this.i18n.translations();
        return WINDOW_DAYS.map((w) => ({ value: w.value, label: this.i18n.t(`dashboard.${w.key}`) }));
    });

    readonly data = signal<DashboardOverview | null>(null);
    readonly securityDebt = signal<SecurityDebtReport | null>(null);
    readonly loading = signal(true);
    readonly error = signal<string | null>(null);

    /**
     * The backlog over time, apart from the overview.
     *
     * Its own request and its own error state. The series is the one thing on this page that
     * loads two timestamps per issue in scope, so it is the one that can be slow or fail on its
     * own — and when it does, the panel says so instead of showing an empty frame that reads as
     * "no issues were ever opened".
     */
    readonly trends = signal<Trends | null>(null);
    readonly postureAnalytics = signal<PostureTrendAnalytics | null>(null);
    readonly trendError = signal<string | null>(null);
    readonly window = signal(90);

    constructor() {
        this.dashboardApi.dashboard().subscribe({
            next: (overview) => {
                this.data.set(overview);
                this.loading.set(false);
            },
            error: () => {
                this.error.set(this.i18n.t('dashboard.load_failed'));
                this.loading.set(false);
            }
        });
        this.remediationApi.getSecurityDebt().subscribe({
            next: (debt) => this.securityDebt.set(debt),
            error: () => {}
        });
        this.loadTrends(this.window());
    }

    /** The series for one window. Cleared before the request, so a slow answer cannot leave the
     *  old curve under a new window's label — a chart labelled 30 days showing a year is a lie
     *  nobody would suspect. */
    loadTrends(days: number): void {
        this.window.set(days);
        this.trends.set(null);
        this.trendError.set(null);
        this.dashboardApi.trends(days).subscribe({
            next: (series) => this.trends.set(series),
            error: () => this.trendError.set(this.i18n.t('dashboard.trend_load_failed'))
        });

        this.dashboardApi.getPostureAnalytics(days).subscribe({
            next: (analytics) => this.postureAnalytics.set(analytics),
            error: () => {}
        });
    }

    gradeSeverity(grade: string): 'success' | 'info' | 'warn' | 'danger' {
        switch (grade) {
            case 'A': return 'success';
            case 'B': return 'info';
            case 'C': return 'warn';
            default: return 'danger';
        }
    }

    /**
     * The mean time to resolve, in words.
     *
     * `null` is **not** rendered as zero: zero reads as "everything is fixed the day it appears",
     * which is the opposite of "nothing was resolved in this window, so there is nothing to
     * measure". The two states look identical in a stat tile, and one of them would flatter the
     * team that fixed nothing.
     */
    meanLabel(): string {
        const mean = this.trends()?.mean_days_to_resolve;
        if (mean === null || mean === undefined) return this.i18n.t('dashboard.no_measurement');
        return this.i18n.t('dashboard.days_count', { count: mean.toFixed(1) });
    }

    /** Why there is no mean, when there is none — a stat with no explanation gets read as a bug. */
    meanCaption(): string {
        const series = this.trends();
        if (!series) return '';
        if (series.mean_days_to_resolve === null || series.mean_days_to_resolve === undefined) {
            return this.i18n.t('dashboard.nothing_resolved_in_window');
        }
        // The denominator, stated beside the average: an average with no population behind it is a
        // number people quote and should not.
        return this.i18n.t('dashboard.mean_population', { count: series.resolved_in_window });
    }

    /**
     * The backlog, on a chart of its own.
     *
     * <h2>Why two charts and not two axes</h2>
     *
     * <p>The backlog and the daily movements differ by two orders of magnitude on a real estate: on
     * a single axis, "opened" and "resolved" flatten onto zero and the panel shows one curve
     * claiming to be three. The diagnosis was right; the remedy — a second axis on the right — was
     * not.
     *
     * <p><b>A dual axis lets a reader see a crossing that means nothing.</b> The relative position
     * of the two curves is fixed by the framing the library chose, not by the data: a reader sees
     * "resolutions rise above the backlog" and concludes something from it, when one more day in
     * the window is enough to move the crossing. On the panel projected in a meeting, that is the
     * costliest mistake of all.
     *
     * <p>Two stacked charts sharing the date axis: nothing is lost, and no crossing is suggested
     * any more.
     */
    readonly backlogChart = computed(() => {
        const points = this.trends()?.points ?? [];
        return {
            labels: points.map((point) => point.day.slice(5)),
            datasets: [
                {
                    label: this.i18n.t('dashboard.chart.open_backlog'),
                    data: points.map((point) => point.open),
                    borderColor: themeColour('--p-primary-500', '#3b82f6'),
                    backgroundColor: 'rgba(59, 130, 246, 0.15)',
                    fill: true,
                    tension: 0.2,
                    pointRadius: 0,
                    borderWidth: 2
                }
            ]
        };
    });

    /** The day's movements, over the same window and the same dates as the backlog. */
    readonly flowChart = computed(() => {
        const points = this.trends()?.points ?? [];
        return {
            labels: points.map((point) => point.day.slice(5)),
            datasets: [
                {
                    label: this.i18n.t('dashboard.chart.opened'),
                    data: points.map((point) => point.opened),
                    borderColor: '#f97316',
                    pointRadius: 0,
                    borderWidth: 1
                },
                {
                    label: this.i18n.t('dashboard.chart.resolved'),
                    data: points.map((point) => point.resolved),
                    borderColor: '#22c55e',
                    pointRadius: 0,
                    borderWidth: 1
                }
            ]
        };
    });

    /**
     * The backlog on top, without date labels.
     *
     * <p>They are carried by the chart below: two sets of dates one under the other repeat the same
     * information and steal the height used to read the curves. That is what makes the two panels a
     * single reading rather than two neighbouring charts.
     */
    readonly backlogOptions = computed(() => this.options(this.i18n.t('dashboard.chart.open_backlog'), false));

    readonly flowOptions = computed(() => this.options(this.i18n.t('dashboard.chart.per_day'), true));

    private options(title: string, showDates: boolean) {
        const text = themeColour('--p-text-muted-color', '#71717a');
        const grid = themeColour('--p-content-border-color', '#e4e4e7');
        return {
            maintainAspectRatio: false,
            // A year of daily points on eight hundred pixels: interpolation is what keeps the
            // shape readable where one pixel holds several days.
            spanGaps: true,
            interaction: { mode: 'index' as const, intersect: false },
            plugins: { legend: { labels: { color: text } } },
            scales: {
                x: {
                    ticks: { color: text, maxTicksLimit: 12, display: showDates },
                    grid: { color: grid }
                },
                y: {
                    beginAtZero: true,
                    title: { display: true, text: title, color: text },
                    ticks: { color: text, precision: 0 },
                    grid: { color: grid }
                }
            }
        };
    }

    /** Three violations at most: beyond that the row becomes a wall of text and the table
     *  stops serving its purpose, which is spotting what to handle. */
    firstViolations(violations: DashboardOverview['failing'][number]['violations']) {
        return violations.slice(0, 3);
    }
}
