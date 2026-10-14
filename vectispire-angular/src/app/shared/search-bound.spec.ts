import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { ChangeDetectionStrategy, Component, Type, signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { FormsModule } from '@angular/forms';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import document from '../../../openapi.json';
import { useEnglish, useFrench } from '@/app/core/testing/english';
import { AuditLog } from '@/app/pages/audit-log/audit-log';
import { BlastRadius } from '@/app/pages/blast-radius/blast-radius';
import { Inventory } from '@/app/pages/inventory/inventory';
import { Issues } from '@/app/pages/issues/issues';
import { SEARCH_MAX_LENGTH, SearchBound, SearchBoundHint } from './search-bound';

interface Operation {
    parameters?: { name: string; schema?: { maxLength?: number } }[];
}

/** The `maxLength` the contract publishes for one query parameter of one route. */
function publishedBound(path: string, parameter: string): number | undefined {
    const paths = document.paths as unknown as Record<string, { get?: Operation }>;
    return paths[path]?.get?.parameters?.find((declared) => declared.name === parameter)?.schema?.maxLength;
}

/**
 * The search boxes stop where the server stops answering.
 *
 * <p>The list routes refuse a free-text search past one figure with a 400. A box without a `maxlength` let
 * a reader type or paste past it and get an error where their results should be; the figure here and the
 * server's are tied through the contract, read back below, and each box is read in the DOM, where the
 * browser enforces it.
 */
describe('the search boxes, bounded as the server bounds them', () => {
    it.each([
        ['/api/v1/issues', 'search'],
        ['/api/v1/audit-log', 'search'],
        ['/api/v1/blast-radius/explore', 'q'],
        ['/api/v1/inventory/search', 'name'],
        ['/api/v1/inventory/versions', 'name']
    ])('%s?%s= is bounded in the contract by the figure the boxes carry', (path, parameter) => {
        expect(publishedBound(path, parameter)).toBe(SEARCH_MAX_LENGTH);
    });

    describe('each box', () => {
        beforeEach(async () => {
            TestBed.resetTestingModule();
            await TestBed.configureTestingModule({
                providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
            }).compileComponents();
            useEnglish();
        }, 20_000);

        function render(component: Type<unknown>): ComponentFixture<unknown> {
            const fixture = TestBed.createComponent(component);
            fixture.detectChanges();
            return fixture;
        }

        function boxIn(fixture: ComponentFixture<unknown>, selector: string): HTMLInputElement {
            const input = (fixture.nativeElement as HTMLElement).querySelector<HTMLInputElement>(selector);
            expect(input, selector).not.toBeNull();
            return input!;
        }

        /** What the box names as its description: the hint, found the way a screen reader finds it. */
        function hintOf(fixture: ComponentFixture<unknown>, input: HTMLInputElement): HTMLElement {
            const id = input.getAttribute('aria-describedby');
            expect(id, 'aria-describedby').toBeTruthy();
            const hint = (fixture.nativeElement as HTMLElement).querySelector<HTMLElement>(`[id="${id}"]`);
            expect(hint, `#${id}`).not.toBeNull();
            return hint!;
        }

        function type(fixture: ComponentFixture<unknown>, input: HTMLInputElement, value: string): void {
            input.value = value;
            input.dispatchEvent(new Event('input'));
            fixture.detectChanges();
        }

        const boxes: [string, Type<unknown>, string][] = [
            ['the backlog', Issues, 'input[aria-label="Search the issues"]'],
            ['the audit log', AuditLog, 'input#q'],
            ['the component search', Inventory, 'input#name'],
            ['the blast radius', BlastRadius, 'input[type="text"]']
        ];

        it.each(boxes)("%s's search box takes no more than the server answers", (_, component, selector) => {
            expect(boxIn(render(component), selector).maxLength).toBe(SEARCH_MAX_LENGTH);
        });

        // The cap alone stopped typing without a word: a pasted search arrived cut and nobody said why.
        it.each(boxes)("%s's search box says so once it is full, and not before", (_, component, selector) => {
            const fixture = render(component);
            const input = boxIn(fixture, selector);
            const hint = hintOf(fixture, input);
            expect(hint.getAttribute('aria-live')).toBe('polite');
            expect(hint.textContent?.trim()).toBe('');

            type(fixture, input, 'x'.repeat(SEARCH_MAX_LENGTH - 1));
            expect(hint.textContent?.trim()).toBe('');

            type(fixture, input, 'x'.repeat(SEARCH_MAX_LENGTH));
            expect(hint.textContent?.trim()).toBe(`${SEARCH_MAX_LENGTH} characters at most`);

            type(fixture, input, 'x'.repeat(SEARCH_MAX_LENGTH - 1));
            expect(hint.textContent?.trim()).toBe('');
        });

        it('the hint has a sentence in French too', () => {
            useFrench();
            const fixture = render(AuditLog);
            const input = boxIn(fixture, 'input#q');
            type(fixture, input, 'x'.repeat(SEARCH_MAX_LENGTH));
            expect(hintOf(fixture, input).textContent?.trim()).toBe(`${SEARCH_MAX_LENGTH} caractères au plus`);
        });

        it('two boxes on one page are described by two hints', () => {
            const fixture = render(TwoBoxes);
            const [first, second] = Array.from(
                (fixture.nativeElement as HTMLElement).querySelectorAll<HTMLInputElement>('input')
            );
            expect(first.getAttribute('aria-describedby')).not.toBe(second.getAttribute('aria-describedby'));
            type(fixture, first, 'x'.repeat(SEARCH_MAX_LENGTH));
            expect(hintOf(fixture, first).textContent?.trim()).not.toBe('');
            expect(hintOf(fixture, second).textContent?.trim()).toBe('');
        });

        // A filter read back from the URL fills the box through the model, with no `input` event.
        it('a value the page writes into a full box shows the hint as typing does', async () => {
            const fixture = render(TwoBoxes);
            const host = fixture.componentInstance as TwoBoxes;
            host.first.set('x'.repeat(SEARCH_MAX_LENGTH));
            fixture.detectChanges();
            await fixture.whenStable();
            fixture.detectChanges();
            const first = (fixture.nativeElement as HTMLElement).querySelector<HTMLInputElement>('input')!;
            expect(first.value.length).toBe(SEARCH_MAX_LENGTH);
            expect(hintOf(fixture, first).textContent?.trim()).toBe(`${SEARCH_MAX_LENGTH} characters at most`);
        });
    });
});

@Component({
    imports: [FormsModule, SearchBound, SearchBoundHint],
    changeDetection: ChangeDetectionStrategy.Eager,
    template: `
        <input vsSearchBound #a="vsSearchBound" [(ngModel)]="first" />
        <vs-search-bound-hint [bound]="a" />
        <input vsSearchBound #b="vsSearchBound" [(ngModel)]="second" />
        <vs-search-bound-hint [bound]="b" />
    `
})
class TwoBoxes {
    readonly first = signal('');
    readonly second = signal('');
}
