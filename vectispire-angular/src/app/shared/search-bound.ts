import {
    ChangeDetectionStrategy,
    Component,
    Directive,
    ElementRef,
    computed,
    inject,
    input,
    signal
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { NgModel } from '@angular/forms';
import { TranslatePipe } from '../core/i18n/translate.pipe';

/**
 * The longest free-text search a list route accepts: `BoundedText.SEARCH_MAX` on the server, published as
 * the `maxLength` of each search parameter in `openapi.json` — the backlog's `search`, the audit log's, the
 * inventory's component `name` and the blast radius's `q`.
 *
 * Every search box carries it as its `maxlength`, so the box stops taking characters where the server would
 * stop answering: past it the route refuses the request with a 400, which a reader typing a search would
 * otherwise meet as an error in place of their results. The spec beside this file reads the figure back
 * from the contract, so the two cannot part without a red test.
 */
export const SEARCH_MAX_LENGTH = 500;

let hints = 0;

/**
 * A search box bounded by {@link SEARCH_MAX_LENGTH}, and able to say so.
 *
 * **The cap alone was silent.** A box with a `maxlength` simply stops taking characters: a pasted search
 * arrives cut, and further typing does nothing, with no word of why. This directive carries the cap and
 * measures the value, so {@link SearchBoundHint} can say "500 characters at most" once the box is full —
 * and the box names that hint as its description, so a screen reader hears it with the field. One
 * directive rather than a `maxlength` and a describedby per page: the four boxes had each spelt the cap.
 */
@Directive({
    selector: 'input[vsSearchBound]',
    exportAs: 'vsSearchBound',
    host: {
        '[attr.maxlength]': 'max',
        '[attr.aria-describedby]': 'hintId',
        '(input)': 'measure()'
    }
})
export class SearchBound {
    readonly max = SEARCH_MAX_LENGTH;
    readonly hintId = `vs-search-bound-${++hints}`;

    private readonly element = inject<ElementRef<HTMLInputElement>>(ElementRef);
    private readonly length = signal(0);

    /** The box holds as much as the server answers: further typing is dropped. */
    readonly reached = computed(() => this.length() >= this.max);

    constructor() {
        // A value the page writes — a filter read back from the URL — fills the box without an `input` event.
        inject(NgModel, { self: true, optional: true })
            ?.valueChanges?.pipe(takeUntilDestroyed())
            .subscribe((value: unknown) => this.length.set(typeof value === 'string' ? value.length : 0));
    }

    measure(): void {
        this.length.set(this.element.nativeElement.value.length);
    }
}

/**
 * The words for a full {@link SearchBound} box, under it.
 *
 * The live region is always in the page and only its text comes and goes: a region inserted with its text
 * already in it is not announced by every screen reader. Empty, it takes no height, so a page placing it in
 * a column without a gap does not move when it is empty.
 */
@Component({
    selector: 'vs-search-bound-hint',
    imports: [TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    template: `
        <small
            class="block text-xs text-muted-color"
            aria-live="polite"
            data-testid="search-bound-hint"
            [id]="bound().hintId"
        >
            @if (bound().reached()) {
                <span class="block mt-1">{{ 'common.search_bound_reached' | translate: { max: bound().max } }}</span>
            }
        </small>
    `
})
export class SearchBoundHint {
    readonly bound = input.required<SearchBound>();
}
