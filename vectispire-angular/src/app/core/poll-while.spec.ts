import { TestBed } from '@angular/core/testing';
import { Component, signal } from '@angular/core';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { anyScanRunning, pollWhile } from './poll-while';

/**
 * The conditional timer.
 *
 * <p>Two ways of getting it wrong, and only one of them shows. A timer that never starts is
 * noticed at the first scan launched. A timer that <em>never</em> stops is not noticed at all: the
 * screen works, and the server receives seven hundred and twenty requests an hour per tab. That is
 * the defect this utility replaces, so every case checks both directions.
 */
describe('pollWhile', () => {
    beforeEach(() => vi.useFakeTimers());
    afterEach(() => vi.useRealTimers());

    function mount(active: ReturnType<typeof signal<boolean>>, refresh: () => void) {
        @Component({ standalone: true, template: '' })
        class Host {
            constructor() {
                pollWhile(active, refresh, 1000);
            }
        }
        const fixture = TestBed.createComponent(Host);
        fixture.detectChanges();
        return fixture;
    }

    it('ne demande rien tant que rien ne bouge', () => {
        const refresh = vi.fn();
        mount(signal(false), refresh);

        vi.advanceTimersByTime(10_000);
        expect(refresh).not.toHaveBeenCalled();
    });

    it('refreshes while things move, and goes quiet once they are settled', () => {
        const refresh = vi.fn();
        const active = signal(true);
        const fixture = mount(active, refresh);

        vi.advanceTimersByTime(3000);
        expect(refresh).toHaveBeenCalledTimes(3);

        active.set(false);
        fixture.detectChanges();
        vi.advanceTimersByTime(10_000);
        expect(refresh).toHaveBeenCalledTimes(3);
    });

    it('restarts when a new scan is launched', () => {
        const refresh = vi.fn();
        const active = signal(false);
        const fixture = mount(active, refresh);

        vi.advanceTimersByTime(5000);
        expect(refresh).not.toHaveBeenCalled();

        active.set(true);
        fixture.detectChanges();
        vi.advanceTimersByTime(2000);
        expect(refresh).toHaveBeenCalledTimes(2);
    });

    it('stops with the screen, not after it', () => {
        // An interval that outlives its component goes on calling the server for nobody, and
        // nothing on screen shows it.
        const refresh = vi.fn();
        const fixture = mount(signal(true), refresh);

        vi.advanceTimersByTime(2000);
        expect(refresh).toHaveBeenCalledTimes(2);

        fixture.destroy();
        vi.advanceTimersByTime(10_000);
        expect(refresh).toHaveBeenCalledTimes(2);
    });
});

describe('anyScanRunning', () => {
    it('ne compte que les statuts qui bougent encore', () => {
        expect(anyScanRunning([{ status: 'completed' }, { status: 'failed' }])).toBe(false);
        expect(anyScanRunning([{ status: 'completed' }, { status: 'pending' }])).toBe(true);
        expect(anyScanRunning([{ status: 'SCANNING' }])).toBe(true);
        // A target never scanned is waiting for nothing: without this case, a fresh list would
        // query the server forever.
        expect(anyScanRunning([null, undefined, {}])).toBe(false);
        expect(anyScanRunning([])).toBe(false);
    });
});
