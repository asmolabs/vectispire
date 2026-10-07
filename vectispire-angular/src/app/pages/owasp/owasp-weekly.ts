import { DatePipe } from '@angular/common';
import {
    Component,
    ElementRef,
    Injector,
    afterNextRender,
    computed,
    inject,
    signal,
    viewChild,
    ChangeDetectionStrategy
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Params, Router, RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { ChartModule } from '@openng/optimus-ui/chart';
import { MessageModule } from '@openng/optimus-ui/message';
import { MultiSelectModule } from '@openng/optimus-ui/multiselect';
import { SelectModule } from '@openng/optimus-ui/select';
import { OwaspApi } from '@/app/core/api/owasp.api';
import { messageOf } from '@/app/core/api-error';
import { saveBlob } from '@/app/core/download';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { TranslatePipe } from '@/app/core/i18n/translate.pipe';
import { LatestRequest } from '@/app/core/latest-request';
import { LayoutService } from '@/app/layout/service/layout.service';
import type { OwaspWeek, OwaspWeekCategory, OwaspWeeklyCoverage } from '@/app/core/api.models';
import { OwaspScope } from '@/app/shared/owasp-scope';
import { OwaspScopePicker } from '@/app/shared/owasp-scope-picker';
import {
    CategoryOrTotal,
    HeatCell,
    WINDOW_SIZES,
    WeeklyView,
    categoriesWithFindings,
    cellClass,
    cellLabel,
    cellOf,
    indicatorsOf,
    isoDay,
    maxOpen,
    openLink,
    openedLink,
    queryOf,
    readView,
    reopenedLink,
    resolvedLink,
    stateLabel,
    sundayOf,
    totalOpenLink,
    viewParams,
    weeklyCsv
} from '@/app/shared/owasp-weekly';

/** Chart.js paints on a canvas, where a CSS variable is no colour: resolved here, with a fallback. */
function themeColour(variable: string, fallback: string): string {
    if (typeof document === 'undefined') return fallback;
    const value = getComputedStyle(document.documentElement).getPropertyValue(variable).trim();
    return value || fallback;
}

/** One colour per category, in the standard's order, distinguishable on light and dark surfaces. */
const PALETTE: Record<string, string> = {
    A01: '#ef4444',
    A02: '#f97316',
    A03: '#eab308',
    A04: '#84cc16',
    A05: '#14b8a6',
    A06: '#3b82f6',
    A07: '#8b5cf6',
    A08: '#ec4899',
    A09: '#78716c',
    A10: '#06b6d4'
};

interface HeatRow {
    category: string;
    title: string;
    cells: { week: OwaspWeek; line: OwaspWeekCategory; cell: HeatCell }[];
}

/**
 * The OWASP Top 10 week by week: a heatmap, the curves of what is open, the week's flows, and the
 * grid of the week a reader picks — each figure opening the backlog it counts.
 *
 * **Two kinds of week, and they must not look alike.** A week the record captured carries the
 * grid's state and leaves settled triage apart; a week from before the record is reconstructed
 * from the issues' dates, has no state, and counts every issue open at its end whatever its
 * triage. A heatmap painting both the same way would put a fall in the backlog on the week the
 * record started — the definition changing, read as progress. So reconstructed squares are
 * hatched, the curves dash over them, and no delta is drawn across the boundary.
 *
 * **The URL is the view.** Window, scope and selected week are query parameters, so a link sent to
 * somebody reproduces what was on screen, and the backlog's "back" lands on the column left.
 */
@Component({
    selector: 'zs-owasp-weekly',
    imports: [
        DatePipe,
        FormsModule,
        RouterLink,
        ButtonModule,
        ChartModule,
        MessageModule,
        MultiSelectModule,
        OwaspScopePicker,
        SelectModule,
        TranslatePipe
    ],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './owasp-weekly.html',
    styleUrl: './owasp-weekly.scss'
})
export class OwaspWeekly {
    private readonly load = new LatestRequest();
    private readonly route = inject(ActivatedRoute);
    private readonly router = inject(Router);
    private readonly owaspApi = inject(OwaspApi);
    private readonly layout = inject(LayoutService);
    private readonly injector = inject(Injector);
    private readonly scroller = viewChild<ElementRef<HTMLElement>>('scroller');
    readonly i18n = inject(I18nService);

    readonly view = signal<WeeklyView>(readView({ get: () => null }, new Date()));
    readonly data = signal<OwaspWeeklyCoverage | null>(null);
    readonly loading = signal(false);
    readonly error = signal<string | null>(null);
    private lastQuery = '';

    /** The curves' categories as chosen; `null` until somebody chooses, which reads as "those with findings". */
    private readonly curvePick = signal<string[] | null>(null);
    /** The flows' category; `null` is the total. */
    readonly flowCategory = signal<string | null>(null);

    /** The range being typed, applied on demand: a date input fires on every keystroke of a year. */
    rangeFrom = '';
    rangeTo = '';

    constructor() {
        this.route.queryParamMap.pipe(takeUntilDestroyed()).subscribe((params) => {
            const view = readView(params, new Date());
            this.view.set(view);
            if (view.window.kind === 'range') {
                this.rangeFrom = view.window.from;
                this.rangeTo = view.window.to;
            }
            this.reload();
        });
    }

    private reload(): void {
        const query = queryOf(this.view(), new Date());
        const key = JSON.stringify(query);
        // Picking a week changes the URL and not the figures: no second request for the same weeks.
        if (key === this.lastQuery && (this.data() !== null || this.loading())) return;
        this.lastQuery = key;
        this.loading.set(true);
        this.error.set(null);
        this.load.run(this.owaspApi.weeklyCoverage(query), {
            next: (coverage) => {
                this.data.set(coverage);
                // The latest week first: on a phone the window scrolls, and it opened on the oldest
                // weeks with the current one out of sight — the column a reader comes for.
                afterNextRender(
                    {
                        write: () => {
                            const scroller = this.scroller()?.nativeElement;
                            if (scroller) scroller.scrollLeft = scroller.scrollWidth;
                        }
                    },
                    { injector: this.injector }
                );
                this.loading.set(false);
            },
            error: (failure) => {
                this.data.set(null);
                this.loading.set(false);
                this.lastQuery = '';
                this.error.set(messageOf(failure, this.i18n.t('owasp_weekly.load_failed')));
            }
        });
    }

    private go(view: WeeklyView): void {
        void this.router.navigate([], { relativeTo: this.route, queryParams: viewParams(view), replaceUrl: true });
    }

    // ---- controls ---------------------------------------------------------------------------------

    readonly windowOptions = computed(() => {
        this.i18n.translations();
        return [
            ...WINDOW_SIZES.map((weeks) => ({
                value: `last:${weeks}`,
                label: this.i18n.t('owasp_weekly.window_last', { weeks })
            })),
            { value: 'range', label: this.i18n.t('owasp_weekly.window_range') }
        ];
    });

    readonly windowValue = computed(() => {
        const window = this.view().window;
        return window.kind === 'range' ? 'range' : `last:${window.weeks}`;
    });

    windowChanged(value: string): void {
        const current = this.view();
        if (value === 'range') {
            const weeks = this.data()?.weeks ?? [];
            this.rangeFrom = weeks[0]?.weekStart ?? '';
            this.rangeTo = weeks[weeks.length - 1]?.weekStart ?? '';
            if (this.rangeFrom && this.rangeTo) {
                this.go({ ...current, window: { kind: 'range', from: this.rangeFrom, to: this.rangeTo } });
            }
            return;
        }
        const weeks = WINDOW_SIZES.find((size) => `last:${size}` === value);
        if (weeks) this.go({ ...current, window: { kind: 'last', weeks }, week: null });
    }

    applyRange(): void {
        const from = isoDay(this.rangeFrom);
        const to = isoDay(this.rangeTo);
        if (from === null || to === null) return;
        this.go({ ...this.view(), window: { kind: 'range', from, to }, week: null });
    }

    scopeChanged(scope: OwaspScope): void {
        this.go({ ...this.view(), scope });
    }

    selectWeek(week: OwaspWeek): void {
        this.go({ ...this.view(), week: week.weekStart });
    }

    // ---- the heatmap ------------------------------------------------------------------------------

    readonly weeks = computed(() => this.data()?.weeks ?? []);
    readonly max = computed(() => maxOpen(this.weeks()));
    readonly anyReconstructed = computed(() => this.weeks().some((week) => week.reconstructed));
    /** Some week of the window began before reopenings were recorded, and shows no figure for them. */
    readonly anyReopenedUnknown = computed(() => this.weeks().some((week) => week.reopened === null));

    readonly rows = computed<HeatRow[]>(() => {
        const weeks = this.weeks();
        const max = this.max();
        const first = weeks[0]?.categories ?? [];
        return first.map((line, index) => ({
            category: line.category,
            title: line.title,
            cells: weeks.map((week) => ({
                week,
                line: week.categories[index],
                cell: cellOf(week, week.categories[index], max)
            }))
        }));
    });

    readonly indicators = computed(() => indicatorsOf(this.weeks(), this.view().week));
    readonly selected = computed(() => this.indicators()?.week ?? null);

    isSelected(week: OwaspWeek): boolean {
        return this.selected()?.weekStart === week.weekStart;
    }

    classOf(cell: HeatCell): string {
        return cellClass(cell);
    }

    /** The square in words — the tooltip, and the accessible name of the link it carries. */
    cellText(category: string, week: OwaspWeek, cell: HeatCell): string {
        this.i18n.translations();
        const parts = [
            this.i18n.t('owasp_weekly.cell_heading', { category, week: week.weekStart }),
            cellLabel(this.i18n, cell.kind)
        ];
        if (cell.kind === 'findings' || cell.reconstructed) {
            parts.push(this.i18n.t('owasp_weekly.cell_open', { count: cell.open }));
        }
        if (cell.settled) parts.push(this.i18n.t('owasp_weekly.cell_settled', { count: cell.settled }));
        if (cell.reconstructed) parts.push(this.i18n.t('owasp_weekly.cell_reconstructed'));
        return parts.join(' · ');
    }

    stateOf(week: OwaspWeek, line: OwaspWeekCategory): string {
        this.i18n.translations();
        return stateLabel(this.i18n, line.state, week.reconstructed);
    }

    private scope() {
        return this.view().scope;
    }

    openParams(week: OwaspWeek, category: string): Params {
        return openLink(week, category, this.scope());
    }

    /** `null` where the week's total is not a list's length — see `totalOpenLink`. */
    totalOpenParams(week: OwaspWeek): Params | null {
        return totalOpenLink(week, this.scope());
    }

    openedParams(week: OwaspWeek, category: CategoryOrTotal): Params {
        return openedLink(week, category, this.scope());
    }

    resolvedParams(week: OwaspWeek, category: CategoryOrTotal): Params {
        return resolvedLink(week, category, this.scope());
    }

    /** `null` on a week before reopenings were recorded, whose figure is unknown. */
    reopenedParams(week: OwaspWeek, category: CategoryOrTotal): Params | null {
        return reopenedLink(week, category, this.scope());
    }

    sunday(week: OwaspWeek): string {
        return sundayOf(week.weekStart);
    }

    // ---- the curves -------------------------------------------------------------------------------

    readonly categoryOptions = computed(() =>
        (this.weeks()[0]?.categories ?? []).map((line) => ({
            value: line.category,
            label: `${line.category} ${line.title}`
        }))
    );

    readonly curveCategories = computed(() => this.curvePick() ?? categoriesWithFindings(this.weeks()));

    curvesChanged(categories: string[]): void {
        this.curvePick.set(categories);
    }

    private labels(): string[] {
        return this.weeks().map((week) => `${week.weekStart.slice(8, 10)}/${week.weekStart.slice(5, 7)}`);
    }

    /** Dashed where the week is reconstructed: its `open` counts settled triage, a recorded one does not. */
    private segment() {
        const weeks = this.weeks();
        return {
            borderDash: (context: { p1DataIndex: number }) =>
                weeks[context.p1DataIndex]?.reconstructed ? [5, 4] : undefined
        };
    }

    readonly curveChart = computed(() => {
        this.i18n.translations();
        const weeks = this.weeks();
        const picked = new Set(this.curveCategories());
        const segment = this.segment();
        const datasets = this.rows()
            .filter((row) => picked.has(row.category))
            .map((row) => ({
                label: row.category,
                data: row.cells.map((cell) => cell.line.open),
                borderColor: PALETTE[row.category] ?? '#64748b',
                backgroundColor: PALETTE[row.category] ?? '#64748b',
                tension: 0.2,
                pointRadius: 2,
                borderWidth: 2,
                segment
            }));
        datasets.push({
            label: this.i18n.t('owasp_weekly.total'),
            data: weeks.map((week) => week.open),
            borderColor: themeColour('--p-text-color', '#334155'),
            backgroundColor: themeColour('--p-text-color', '#334155'),
            tension: 0.2,
            pointRadius: 2,
            borderWidth: 3,
            segment
        });
        return { labels: this.labels(), datasets };
    });

    readonly flowChart = computed(() => {
        this.i18n.translations();
        const category = this.flowCategory();
        const lines = this.weeks().map((week) =>
            category === null ? week : (week.categories.find((line) => line.category === category) ?? null)
        );
        return {
            labels: this.labels(),
            datasets: [
                {
                    label: this.i18n.t('owasp_weekly.opened'),
                    data: lines.map((line) => line?.opened ?? 0),
                    backgroundColor: '#f97316'
                },
                {
                    // Drawn downwards: a resolution takes away from the backlog, and two bars side by
                    // side upwards read as two kinds of growth.
                    label: this.i18n.t('owasp_weekly.resolved'),
                    data: lines.map((line) => -(line?.resolved ?? 0)),
                    backgroundColor: '#22c55e'
                },
                {
                    // Stacked on the opened: an issue coming back adds to the backlog as a new one does,
                    // and is what makes the open curve rise where the opened bar does not. No bar at
                    // all — not a zero — on a week before reopenings were recorded.
                    label: this.i18n.t('owasp_weekly.reopened'),
                    data: lines.map((line) => (line === null ? 0 : line.reopened)),
                    backgroundColor: '#a855f7'
                }
            ]
        };
    });

    readonly curveOptions = computed(() => this.options(this.i18n.t('owasp_weekly.open_axis'), false));
    /**
     * The flows' axis, on a step that lands on zero. Left to Chart.js, a range of -5 to 3 was ticked
     * every two from the top — 3, 1, -1, -3, -5 — which, shown as absolute values, read "3 1 1 3 5"
     * with no zero line between the opened and the resolved.
     */
    readonly flowOptions = computed(() => {
        const [openedBars, resolvedBars, reopenedBars] = this.flowChart().datasets.map((set) => set.data);
        // The opened and the reopened stack upwards: the axis holds their sum, week by week.
        const opened = Math.max(0, ...openedBars.map((value, index) => (value ?? 0) + (reopenedBars[index] ?? 0)));
        const resolved = Math.max(0, ...resolvedBars.map((value) => Math.abs(value ?? 0)));
        const step = Math.max(1, Math.ceil(Math.max(opened, resolved) / 3));
        const options = this.options(this.i18n.t('owasp_weekly.flow_axis'), true);
        return {
            ...options,
            scales: {
                ...options.scales,
                y: {
                    ...options.scales.y,
                    min: -Math.max(1, Math.ceil(resolved / step)) * step,
                    max: Math.max(1, Math.ceil(opened / step)) * step,
                    ticks: { ...options.scales.y.ticks, stepSize: step }
                }
            }
        };
    });

    private options(title: string, stacked: boolean) {
        // Read so that the colours follow the theme when it changes: a canvas does not restyle itself.
        this.layout.isDarkTheme();
        const text = themeColour('--p-text-muted-color', '#71717a');
        const grid = themeColour('--p-content-border-color', '#e4e4e7');
        return {
            maintainAspectRatio: false,
            interaction: { mode: 'index' as const, intersect: false },
            plugins: {
                legend: { labels: { color: text } },
                tooltip: {
                    callbacks: {
                        // The resolved bars are drawn below zero; their tooltip says how many, not minus how many.
                        label: (item: { dataset: { label?: string }; raw: unknown }) =>
                            `${item.dataset.label ?? ''}: ${Math.abs(Number(item.raw))}`
                    }
                }
            },
            scales: {
                x: { stacked, ticks: { color: text, maxTicksLimit: 13 }, grid: { color: grid } },
                y: {
                    stacked,
                    beginAtZero: true,
                    title: { display: true, text: title, color: text },
                    ticks: { color: text, precision: 0, callback: (value: number | string) => Math.abs(Number(value)) },
                    grid: { color: grid }
                }
            }
        };
    }

    /**
     * A bar opens the issues it counts, the total's included: the backlog's `owasp_category=any` lists
     * the issues placed in some category, which is what the total counts — never the whole backlog,
     * whose licence and quality findings are in no category and would make the list longer than the bar.
     */
    flowSelected(event: { element?: { index: number; datasetIndex: number } }): void {
        const category = this.flowCategory();
        const element = event.element;
        const week = element ? this.weeks()[element.index] : undefined;
        if (!element || !week) return;
        const params = [
            () => this.openedParams(week, category),
            () => this.resolvedParams(week, category),
            () => this.reopenedParams(week, category)
        ][element.datasetIndex]?.();
        if (params) void this.router.navigate(['/issues'], { queryParams: params });
    }

    flowChanged(category: string | null): void {
        this.flowCategory.set(category);
    }

    // ---- exports ----------------------------------------------------------------------------------

    /** Built here from what is on screen: the figures are already loaded, and a server route would be a second copy. */
    downloadCsv(): void {
        const coverage = this.data();
        if (!coverage) return;
        const body = new Blob([weeklyCsv(coverage)], { type: 'text/csv;charset=utf-8' });
        const scope = coverage.scope ? `-${coverage.scope.kind}-${coverage.scope.id}` : '';
        saveBlob(body, `vectispire-owasp-weekly${scope}-${coverage.from}-${coverage.to}.csv`);
    }

    /** The browser's own "save as PDF": no PDF library, and the print stylesheet keeps the figures only. */
    print(): void {
        window.print();
    }

    delta(value: number | null): string {
        if (value === null) return '—';
        return value > 0 ? `+${value}` : String(value);
    }
}
