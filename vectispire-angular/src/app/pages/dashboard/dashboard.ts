import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { ChartModule } from '@openng/optimus-ui/chart';
import { MessageModule } from '@openng/optimus-ui/message';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { ApiService } from '../../core/api.service';
import type { DashboardOverview, Trends, PostureTrendAnalytics, SecurityDebtReport } from '../../core/api.models';
import { LastScanTag } from '../../shared/last-scan';

/** The severities in descending order, with their colour. A fixed order, not derived from the
 *  data: otherwise two successive loads could present them differently. */
const SEVERITIES = [
    { key: 'critical', label: 'Critical', severity: 'danger' as const },
    { key: 'high', label: 'High', severity: 'warn' as const },
    { key: 'medium', label: 'Medium', severity: 'secondary' as const },
    { key: 'low', label: 'Low', severity: 'secondary' as const }
];

/** The windows offered. Days, because that is the unit the route clamps and the axis shows. */
const WINDOWS = [
    { label: '30 days', value: 30 },
    { label: '90 days', value: 90 },
    { label: '1 year', value: 365 }
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
    templateUrl: './dashboard.html'
})
export class Dashboard {
    private readonly api = inject(ApiService);
    readonly severities = SEVERITIES;
    readonly windows = WINDOWS;

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
        this.api.dashboard().subscribe({
            next: (overview) => {
                this.data.set(overview);
                this.loading.set(false);
            },
            error: () => {
                this.error.set('Could not load the dashboard.');
                this.loading.set(false);
            }
        });
        this.api.getSecurityDebt().subscribe({
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
        this.api.trends(days).subscribe({
            next: (series) => this.trends.set(series),
            error: () => this.trendError.set('Could not load the backlog trend.')
        });

        this.api.getPostureAnalytics(days).subscribe({
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
        if (mean === null || mean === undefined) return 'No measurement';
        return `${mean.toFixed(1)} days`;
    }

    /** Why there is no mean, when there is none — a stat with no explanation gets read as a bug. */
    meanCaption(): string {
        const series = this.trends();
        if (!series) return '';
        if (series.mean_days_to_resolve === null || series.mean_days_to_resolve === undefined) {
            return 'Nothing was resolved in this window: there is nothing to average.';
        }
        // The denominator, stated beside the average: an average with no population behind it is a
        // number people quote and should not.
        return `over ${series.resolved_in_window} issue(s) resolved in this window`;
    }

    /**
     * The two curves, on two axes.
     *
     * The standing backlog and the daily movements differ by two orders of magnitude on a real
     * install: drawn against one axis, "opened" and "resolved" flatten onto zero and the panel
     * shows one line pretending to be three. Hence the second scale on the right, and the axis
     * titles that say which is which.
     */
    readonly chartData = computed(() => {
        const points = this.trends()?.points ?? [];
        return {
            labels: points.map((point) => point.day.slice(5)),
            datasets: [
                {
                    label: 'Open backlog',
                    data: points.map((point) => point.open),
                    borderColor: themeColour('--p-primary-500', '#3b82f6'),
                    backgroundColor: 'rgba(59, 130, 246, 0.15)',
                    fill: true,
                    tension: 0.2,
                    pointRadius: 0,
                    borderWidth: 2,
                    yAxisID: 'y'
                },
                {
                    label: 'Opened',
                    data: points.map((point) => point.opened),
                    borderColor: '#f97316',
                    pointRadius: 0,
                    borderWidth: 1,
                    yAxisID: 'flows'
                },
                {
                    label: 'Resolved',
                    data: points.map((point) => point.resolved),
                    borderColor: '#22c55e',
                    pointRadius: 0,
                    borderWidth: 1,
                    yAxisID: 'flows'
                }
            ]
        };
    });

    readonly chartOptions = computed(() => {
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
                x: { ticks: { color: text, maxTicksLimit: 12 }, grid: { color: grid } },
                y: {
                    position: 'left' as const,
                    beginAtZero: true,
                    title: { display: true, text: 'Open backlog', color: text },
                    ticks: { color: text, precision: 0 },
                    grid: { color: grid }
                },
                flows: {
                    position: 'right' as const,
                    beginAtZero: true,
                    title: { display: true, text: 'Per day', color: text },
                    ticks: { color: text, precision: 0 },
                    // One grid only: two sets of horizontal lines at different intervals read as
                    // a fault in the rendering.
                    grid: { display: false }
                }
            }
        };
    });

    /** Three violations at most: beyond that the row becomes a wall of text and the table
     *  stops serving its purpose, which is spotting what to handle. */
    firstViolations(violations: DashboardOverview['failing'][number]['violations']) {
        return violations.slice(0, 3);
    }
}
