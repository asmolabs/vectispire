import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { Title } from '@angular/platform-browser';
import { TitleStrategy, provideRouter } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { appRoutes } from '../../../app.routes';
import { useEnglish } from '../testing/english';
import { I18nService } from './i18n.service';
import { TranslatedTitleStrategy } from './translated-title.strategy';

/** The tab title, through the application's own route table so that a route without one shows. */
describe('the tab title', () => {
    beforeEach(() => {
        TestBed.resetTestingModule();
        TestBed.configureTestingModule({
            providers: [
                provideRouter(appRoutes),
                provideHttpClient(withXhr()),
                provideHttpClientTesting(),
                { provide: TitleStrategy, useExisting: TranslatedTitleStrategy }
            ]
        });
        useEnglish();
    });

    it('names the page, and names it again in the language chosen afterwards', async () => {
        const harness = await RouterTestingHarness.create();
        await harness.navigateByUrl('/notfound');
        TestBed.tick();
        expect(TestBed.inject(Title).getTitle()).toBe('Page not found · Vectispire');

        // Kept as a key, not as the text: switching language must reach the tab already open.
        TestBed.inject(I18nService).translations.set({ titles: { notfound: 'Page non trouvée' } });
        TestBed.tick();
        expect(TestBed.inject(Title).getTitle()).toBe('Page non trouvée · Vectispire');
    });

    it('gives every page a title', () => {
        // A route left without one keeps whatever the previous page set, which is worse than none.
        const untitled = (routes: typeof appRoutes, prefix = ''): string[] =>
            routes.flatMap((route) => {
                const path = [prefix, route.path].filter(Boolean).join('/');
                const own = route.redirectTo || route.children || route.title ? [] : [path];
                return [...own, ...untitled(route.children ?? [], path)];
            });
        expect(untitled(appRoutes)).toEqual([]);
    });
});
