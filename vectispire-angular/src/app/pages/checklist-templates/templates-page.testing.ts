import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { Type } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import type { ChecklistPreview, ChecklistTemplate, ChecklistVersion } from '@/app/core/api.models';
import { SessionStore } from '@/app/core/session.store';
import { useEnglish } from '@/app/core/testing/english';
import { sessionUser } from '@/app/core/testing/session.fixtures';
import { draftFrom } from './templates-model';
import { TemplatesPage } from './templates-page';

/** What a part of the templates screen is mounted over: the page's state, as the reads would have left it. */
export interface Seed {
    role?: string;
    username?: string;
    templates?: ChecklistTemplate[];
    preview?: ChecklistPreview | null;
    version?: ChecklistVersion | null;
}

export const TEMPLATES_URL = '/api/v1/checklist-templates';
export const VERSION_URL = `${TEMPLATES_URL}/release/versions/2`;

/**
 * One component of the checklist templates screen, mounted on its own over a `TemplatesPage` seeded as
 * if version 2 of `release` were open — the list read is answered here, so the requests a spec sees
 * are the component's. The page's own suites read the same parts through the routes.
 */
export function mountOnTemplates<T>(
    component: Type<T>,
    seed: Seed = {}
): { fixture: ComponentFixture<T>; page: TemplatesPage; http: HttpTestingController; dom: () => HTMLElement } {
    TestBed.configureTestingModule({
        imports: [component],
        providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([]), TemplatesPage]
    });
    TestBed.inject(SessionStore).open('token', sessionUser(seed.role ?? 'CISO', { username: seed.username ?? 'bob' }));
    useEnglish();
    const http = TestBed.inject(HttpTestingController);
    const page = TestBed.inject(TemplatesPage);
    http.expectOne(TEMPLATES_URL).flush(seed.templates ?? []);
    if (seed.preview) {
        page.selected.set({ slug: seed.preview.templateSlug, ordinal: seed.preview.version.ordinal });
        page.preview.set(seed.preview);
        page.layoutDraft.set(draftFrom(seed.preview));
    }
    page.version.set(seed.version ?? null);
    const fixture = TestBed.createComponent(component);
    fixture.detectChanges();
    return { fixture, page, http, dom: () => fixture.nativeElement as HTMLElement };
}

/** The `<button>` a `p-button` renders, by the host's id or by its accessible name or text. */
export function buttonIn(dom: HTMLElement, idOrName: string): HTMLButtonElement {
    const host = dom.querySelector(`[id="${idOrName}"]`);
    const found =
        host?.tagName === 'BUTTON'
            ? host
            : (host?.querySelector('button') ??
              Array.from(dom.querySelectorAll('button')).find(
                  (candidate) =>
                      candidate.getAttribute('aria-label') === idOrName || candidate.textContent?.trim() === idOrName
              ));
    if (!found) throw new Error(`no button ${idOrName}`);
    return found as HTMLButtonElement;
}

export const textOf = (dom: HTMLElement, selector: string): string =>
    dom.querySelector(selector)?.textContent?.replace(/\s+/g, ' ').trim() ?? '';

export function typeInto(dom: HTMLElement, selector: string, value: string): void {
    const input = dom.querySelector<HTMLInputElement>(selector)!;
    input.value = value;
    input.dispatchEvent(new Event('input'));
}
