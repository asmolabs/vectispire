import { provideHttpClient } from '@angular/common/http';
import { ChangeDetectionStrategy, Component, signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { I18nService } from './i18n.service';
import { TranslatePipe } from './translate.pipe';

/**
 * The translate pipe answers again only when its key, its parameters or the language change — and
 * still follows a switch of language on a page already drawn, which a pure pipe would not.
 */
@Component({
    imports: [TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    template: `<span id="plain">{{ 'demo.title' | translate }}</span
        ><span id="count">{{ 'demo.items' | translate: { count: count() } }}</span
        ><span id="built">{{ 'demo.items' | translate: params() }}</span>`
})
class Host {
    readonly count = signal(1);
    readonly built = signal(2);
    /** A new object on every pass, as a method building the parameters would hand over. */
    params(): Record<string, number> {
        return { count: this.built() };
    }
}

const ENGLISH = { demo: { title: 'Projects', items_one: '{{count}} item', items_other: '{{count}} items' } };
const FRENCH = { demo: { title: 'Projets', items_one: '{{count}} élément', items_other: '{{count}} éléments' } };

describe('translate', () => {
    beforeEach(() => {
        TestBed.resetTestingModule();
        TestBed.configureTestingModule({ providers: [provideHttpClient()] });
    });

    const render = () => {
        const i18n = TestBed.inject(I18nService);
        const fixture = TestBed.createComponent(Host);
        const text = (id: string) => (fixture.nativeElement as HTMLElement).querySelector(`#${id}`)!.textContent;
        return { i18n, fixture, text };
    };

    it('shows the key until the bundle arrives, then the sentence', () => {
        const { i18n, fixture, text } = render();
        fixture.detectChanges();
        expect(text('plain')).toBe('demo.title');

        i18n.translations.set(ENGLISH);
        fixture.detectChanges();
        expect(text('plain')).toBe('Projects');
    });

    it('rewrites what is on screen when the language changes', () => {
        const { i18n, fixture, text } = render();
        i18n.translations.set(ENGLISH);
        fixture.detectChanges();
        expect([text('plain'), text('count'), text('built')]).toEqual(['Projects', '1 item', '2 items']);

        i18n.translations.set(FRENCH);
        i18n.currentLang.set('fr');
        fixture.detectChanges();
        expect([text('plain'), text('count'), text('built')]).toEqual(['Projets', '1 élément', '2 éléments']);
    });

    it('looks nothing up again on a pass where nothing changed', () => {
        const { i18n, fixture, text } = render();
        i18n.translations.set(ENGLISH);
        fixture.detectChanges();
        const lookups = vi.spyOn(i18n, 't');

        fixture.componentRef.changeDetectorRef.markForCheck();
        fixture.detectChanges();
        expect(lookups).not.toHaveBeenCalled();

        fixture.componentInstance.count.set(3);
        fixture.detectChanges();
        expect(lookups).toHaveBeenCalledTimes(1);
        expect(text('count')).toBe('3 items');

        fixture.componentInstance.built.set(1);
        fixture.detectChanges();
        expect(lookups).toHaveBeenCalledTimes(2);
        expect(text('built')).toBe('1 item');
    });

    it('answers an empty key with nothing', () => {
        const pipe = TestBed.runInInjectionContext(() => new TranslatePipe());
        expect(pipe.transform('')).toBe('');
    });
});
