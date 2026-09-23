import { DestroyRef, inject } from '@angular/core';
import { Observable, Observer, Subscription } from 'rxjs';

/**
 * One request slot whose <b>latest request wins</b>: starting one cancels the one still in flight.
 *
 * <p><b>Why.</b> Every filtered screen subscribed a fresh request on each change and let the old
 * one run. Answers do not come back in the order they were asked, so toggling two filters quickly
 * could leave the table showing the first filter's rows under the second filter's controls — and
 * on the issues screen a bulk triage then landed on rows the operator was no longer looking at.
 * Unsubscribing an {@code HttpClient} observable aborts the request, so the stale answer never
 * arrives at all.
 *
 * <p>One instance per independent stream: a screen that loads a summary and a table separately
 * holds two, or cancelling the table would cancel the summary. Created in an injection context —
 * a field initialiser — so the request in flight is cancelled with the screen as well.
 */
export class LatestRequest {
    private current: Subscription | null = null;

    constructor() {
        inject(DestroyRef).onDestroy(() => this.cancel());
    }

    run<T>(source: Observable<T>, observer: Partial<Observer<T>>): void {
        this.cancel();
        this.current = source.subscribe(observer);
    }

    cancel(): void {
        this.current?.unsubscribe();
        this.current = null;
    }
}
