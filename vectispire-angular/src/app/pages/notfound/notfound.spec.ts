import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter, Router, UrlTree } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { appRoutes } from '@/app.routes';
import { useEnglish, useFrench } from '@/app/core/testing/english';

/**
 * The page an address nobody serves lands on. The routes that were renamed or removed send their old
 * paths here through the catch-all, so it is the page a stale bookmark opens: it has to say what
 * happened and offer somewhere real to go — through the application's own routes, so that a
 * catch-all lost in a reorder of `app.routes.ts` fails here and not on a bookmark.
 */
describe('the page not found', () => {
    let harness: RouterTestingHarness;
    let page: HTMLElement;

    beforeEach(async () => {
        TestBed.resetTestingModule();
        TestBed.configureTestingModule({
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter(appRoutes)]
        });
        useEnglish();
        harness = await RouterTestingHarness.create();
        await harness.navigateByUrl('/an/address/nobody/serves');
        page = harness.routeNativeElement as HTMLElement;
    });

    it('is where an unknown address lands, and says so', () => {
        expect(TestBed.inject(Router).url).toBe('/notfound');
        expect(page.querySelector('h1')?.textContent.trim()).toBe('Page not found');
    });

    it('offers the security posture, the issues and the repositories, each by its name', () => {
        const links = [...page.querySelectorAll('a')].map((link) => ({
            href: link.getAttribute('href'),
            name: link.textContent.replace(/\s+/g, ' ').trim()
        }));

        expect(links.map((link) => link.href)).toEqual(['/security', '/issues', '/repositories']);
        for (const link of links) {
            expect(link.name).not.toBe('');
            expect(link.name).not.toMatch(/menu\.|\.subtitle/);
        }
    });

    it('takes the reader back to the dashboard, in French for a French reader', () => {
        useFrench();
        harness.detectChanges();

        expect(page.querySelector('h1')?.textContent.trim()).toBe('Page non trouvée');
        const back = [...page.querySelectorAll('p-button')].find((button) =>
            button.textContent.includes('Retour au tableau de bord')
        );
        expect(back).toBeDefined();

        // The dashboard is behind the session guard, which is not this page's to exercise: what the
        // button asks the router for is what matters here.
        const router = TestBed.inject(Router);
        const navigate = vi.spyOn(router, 'navigateByUrl').mockResolvedValue(true);
        back!.querySelector('button')!.click();
        expect(navigate).toHaveBeenCalledTimes(1);
        expect(router.serializeUrl(navigate.mock.calls[0][0] as UrlTree)).toBe('/');
    });
});
