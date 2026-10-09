import { provideHttpClient } from '@angular/common/http';
import { Component, ChangeDetectionStrategy } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { I18nService } from './i18n.service';
import { LocalNumberPipe } from './local-number.pipe';

/**
 * A figure in the reader's mark, and an absent figure left absent.
 *
 * Read through the DOM: the pipe is impure precisely so that switching the language rewrites a figure
 * already on screen, and only a rendered template can show it does.
 */
@Component({
    imports: [LocalNumberPipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    template: `<span id="days">{{ 11.4 | localNumber }}</span
        ><span id="fixed">{{ 5 | localNumber: 1 : 1 }}</span
        ><span id="none">{{ (missing | localNumber) ?? '—' }}</span>`
})
class Host {
    readonly missing: number | null = null;
}

describe('localNumber', () => {
    beforeEach(() => {
        TestBed.resetTestingModule();
        TestBed.configureTestingModule({ providers: [provideHttpClient()] });
    });

    it('writes the decimal mark of the current language, and follows a switch', () => {
        const i18n = TestBed.inject(I18nService);
        const fixture = TestBed.createComponent(Host);
        const text = (id: string) => (fixture.nativeElement as HTMLElement).querySelector(`#${id}`)!.textContent;

        fixture.detectChanges();
        expect(text('days')).toBe('11.4');
        expect(text('fixed')).toBe('5.0');

        i18n.currentLang.set('fr');
        fixture.detectChanges();
        expect(text('days')).toBe('11,4');
        expect(text('fixed')).toBe('5,0');
    });

    it('leaves a missing figure to the template, never "0"', () => {
        const fixture = TestBed.createComponent(Host);
        fixture.detectChanges();
        expect((fixture.nativeElement as HTMLElement).querySelector('#none')!.textContent).toBe('—');
    });

    it('answers a dash for what is no number', () => {
        const pipe = TestBed.runInInjectionContext(() => new LocalNumberPipe());
        expect(pipe.transform(Number.NaN)).toBe('—');
        expect(pipe.transform(undefined)).toBeNull();
    });
});
