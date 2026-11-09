/**
 * A dated vertical line on a line chart, with an optional label at its top — the day the scorecard
 * formula changed (decision 0036), on the dashboard's trend chart.
 *
 * **Why a plugin of our own.** Chart.js draws on a canvas and has no vertical marker of its own; the
 * annotation plugin that has one is a dependency for one line. This draws after the datasets, at the
 * x of the point whose index the chart's options name (`plugins.datedMarker.index`), and nothing when
 * the index is absent or negative — the day outside the window draws no line rather than one at the
 * edge, which would read as "the formula changed when this window starts".
 *
 * A canvas says nothing to a screen reader: the page states the same day in words beside the chart.
 */
export interface DatedMarkerOptions {
    /** The index of the point the line stands on; negative or absent for no line. */
    index?: number;
    /** Written at the top of the line; absent on a chart that only repeats the line. */
    label?: string;
    colour?: string;
}

/** The part of a Chart.js chart the marker draws with, so the plugin is testable without a canvas. */
export interface MarkerChart {
    ctx: Pick<
        CanvasRenderingContext2D,
        | 'save'
        | 'restore'
        | 'beginPath'
        | 'moveTo'
        | 'lineTo'
        | 'stroke'
        | 'setLineDash'
        | 'fillText'
        | 'strokeStyle'
        | 'fillStyle'
        | 'lineWidth'
        | 'font'
        | 'textAlign'
    >;
    chartArea: { top: number; bottom: number };
    scales: { x: { getPixelForValue(value: number): number } };
}

export const DATED_MARKER = {
    id: 'datedMarker',
    afterDatasetsDraw(chart: MarkerChart, _args: unknown, options: DatedMarkerOptions | undefined): void {
        const index = options?.index;
        if (index === undefined || index < 0) return;
        const x = chart.scales.x.getPixelForValue(index);
        const { top, bottom } = chart.chartArea;
        const ctx = chart.ctx;
        const colour = options?.colour ?? '#71717a';
        ctx.save();
        ctx.strokeStyle = colour;
        ctx.lineWidth = 1;
        ctx.setLineDash([4, 3]);
        ctx.beginPath();
        ctx.moveTo(x, top);
        ctx.lineTo(x, bottom);
        ctx.stroke();
        if (options?.label) {
            ctx.setLineDash([]);
            ctx.fillStyle = colour;
            ctx.font = '11px sans-serif';
            ctx.textAlign = 'left';
            ctx.fillText(options.label, x + 4, top + 11);
        }
        ctx.restore();
    }
};
