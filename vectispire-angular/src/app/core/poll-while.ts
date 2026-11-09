import { DestroyRef, Signal, effect, inject } from '@angular/core';

/** The scan statuses that have not finished moving. Everything else is settled. */
export const UNSETTLED_SCAN_STATUSES: readonly string[] = ['pending', 'scanning'];

/** True as soon as one of the scans passed in has not finished. */
export function anyScanRunning(scans: readonly ({ status?: string } | null | undefined)[]): boolean {
    return scans.some((s) => !!s && UNSETTLED_SCAN_STATUSES.includes((s.status ?? '').toLowerCase()));
}

/**
 * Refreshes a screen <b>as long as something is moving</b>, and goes quiet once it is over.
 *
 * <p><b>Why not an SSE stream.</b> The session token lives in memory rather than in a cookie — a
 * deliberate choice of {@code SessionStore} — and {@code EventSource} cannot set an
 * {@code Authorization} header: the bearer would have to go in the URL, and therefore into access
 * logs and proxies. On top of that come two costs a status pill does not justify: a stream is
 * pinned to one instance although the control plane supports several, and it would have to be
 * filtered per subscriber through {@code VisibilityService}, on a surface the route tests do not
 * see. What is being watched changes three times in ten minutes; this is a problem of waiting on a
 * page, not of live data.
 *
 * <p><b>Conditional, and that is the whole point.</b> The agents screen queried the server every
 * five seconds permanently — 720 requests an hour per open tab, on an idle estate. The timer only
 * restarts here when {@code active} becomes true again, so an estate doing nothing costs nothing.
 *
 * <p>To be called in an injection context. Clean-up follows the component's destruction: an
 * interval that outlives its screen goes on calling the server for nobody.
 *
 * @param active true as long as there is something left to wait for
 * @param refresh what to read again; never called immediately, the screen has just loaded
 * @param everyMs the step, generous by default: a scan takes minutes, not milliseconds
 */
export function pollWhile(active: Signal<boolean>, refresh: () => void, everyMs = 5000): void {
    const destroyRef = inject(DestroyRef);
    let handle: ReturnType<typeof setInterval> | null = null;

    const stop = () => {
        if (handle !== null) {
            clearInterval(handle);
            handle = null;
        }
    };

    effect(() => {
        // Read inside the effect: it is what restarts the timer when a scan is launched again.
        if (active()) {
            if (handle === null) {
                handle = setInterval(refresh, everyMs);
            }
        } else {
            stop();
        }
    });

    destroyRef.onDestroy(stop);
}
