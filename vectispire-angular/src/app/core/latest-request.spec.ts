import { TestBed } from '@angular/core/testing';
import { Component } from '@angular/core';
import { Subject } from 'rxjs';
import { describe, expect, it } from 'vitest';
import { LatestRequest } from './latest-request';

/**
 * Latest request wins.
 *
 * <p>The defect it replaces showed only when answers arrived out of order: the first filter's rows
 * under the second filter's controls, and a bulk triage landing on them. So the cases below answer
 * in the wrong order on purpose.
 */
describe('LatestRequest', () => {
    function mount() {
        @Component({ standalone: true, template: '' })
        class Host {
            readonly slot = new LatestRequest();
        }
        const fixture = TestBed.createComponent(Host);
        fixture.detectChanges();
        return fixture;
    }

    it('drops the answer to a request that was superseded, even when it arrives last', () => {
        const { slot } = mount().componentInstance;
        const first = new Subject<string>();
        const second = new Subject<string>();
        const shown: string[] = [];

        slot.run(first, { next: (value) => shown.push(value) });
        slot.run(second, { next: (value) => shown.push(value) });
        second.next('filter B');
        first.next('filter A');

        expect(shown).toEqual(['filter B']);
        expect(first.observed).toBe(false);
    });

    it('cancels the request in flight when the screen goes away', () => {
        const fixture = mount();
        const pending = new Subject<string>();
        fixture.componentInstance.slot.run(pending, {});

        fixture.destroy();

        expect(pending.observed).toBe(false);
    });
});
