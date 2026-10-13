import { Component } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { useEnglish, useFrench } from '@/app/core/testing/english';
import { Error as ErrorPage } from './error';

@Component({ template: '<p data-testid="dashboard">dashboard</p>' })
class Dashboard {}

/**
 * The error page, as the person who reached it reads it: what happened, and one way back. It is a
 * screen nobody opens on an ordinary day, which is why it once pulled its illustration from a CDN the
 * CSP refuses and nobody saw — so what it shows is pinned here rather than trusted.
 */
describe('the error page', () => {
    let harness: RouterTestingHarness;
    let page: HTMLElement;

    beforeEach(async () => {
        TestBed.resetTestingModule();
        TestBed.configureTestingModule({
            providers: [
                provideRouter([
                    { path: '', component: Dashboard },
                    { path: 'error', component: ErrorPage }
                ])
            ]
        });
        useEnglish();
        harness = await RouterTestingHarness.create();
        await harness.navigateByUrl('/error');
        page = harness.routeNativeElement as HTMLElement;
    });

    const buttons = (): HTMLButtonElement[] => [...page.querySelectorAll('button')];
    /** The accessible name, in the order a screen reader computes it: label, text, then the title. */
    const nameOf = (button: HTMLButtonElement): string =>
        (button.getAttribute('aria-label') || button.textContent.trim() || button.getAttribute('title') || '').trim();

    it('says what happened, and takes the reader back to the dashboard', async () => {
        expect(page.querySelector('h1')?.textContent.trim()).toBe('Error Occurred');
        expect(page.textContent).toContain('Requested resource is not available.');

        const back = buttons().find((button) => button.textContent.includes('Go to Dashboard'));
        expect(back).toBeDefined();
        back!.click();
        await harness.fixture.whenStable();

        expect(TestBed.inject(Router).url).toBe('/');
        expect(harness.routeNativeElement?.querySelector('[data-testid="dashboard"]')).not.toBeNull();
    });

    it('names every button, the theme switches included, which show an icon only', () => {
        // The floating configurator brings its own: the theme switch and the appearance menu, icon
        // only, and the swatches of the menu, each named by its palette's title.
        for (const button of buttons()) {
            expect(nameOf(button), button.outerHTML).not.toBe('');
        }
        const labels = buttons().map((button) => button.getAttribute('aria-label'));
        expect(labels).toContain('Appearance');
        expect(labels).toContain('Switch to dark theme');
    });

    it('speaks French to a French reader', () => {
        useFrench();
        harness.detectChanges();

        expect(page.querySelector('h1')?.textContent.trim()).toBe('Une erreur est survenue');
        expect(buttons().some((button) => button.textContent.includes('Retour au tableau de bord'))).toBe(true);
    });
});
