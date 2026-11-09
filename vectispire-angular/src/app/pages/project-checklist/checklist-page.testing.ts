import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { Type } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import type {
    ChecklistMeasurements,
    ChecklistOfferedVersion,
    ChecklistRevisionSummary,
    ChecklistView
} from '@/app/core/api.models';
import { SessionStore } from '@/app/core/session.store';
import { PROJECT_ID, SIGNED_REVISION } from '@/app/core/testing/checklists.fixtures';
import { useEnglish } from '@/app/core/testing/english';
import { sessionUser } from '@/app/core/testing/session.fixtures';
import { ChecklistPage } from './checklist-page';

/** What a part of the checklist screen is mounted over: the page's state, as a read would have left it. */
export interface Seed {
    role?: string;
    username?: string;
    view?: ChecklistView | null;
    revisions?: ChecklistRevisionSummary[];
    measurements?: ChecklistMeasurements | null;
    offered?: ChecklistOfferedVersion[];
}

/**
 * One component of the project checklist screen, mounted on its own over a `ChecklistPage` seeded as
 * if the screen had read the revision — no read is sent, so the requests a spec sees are the
 * component's. The page's own suite reads the same parts through the routes.
 */
export function mountOnPage<T>(
    component: Type<T>,
    seed: Seed = {},
    inputs: Record<string, unknown> = {}
): { fixture: ComponentFixture<T>; page: ChecklistPage; http: HttpTestingController; dom: () => HTMLElement } {
    TestBed.configureTestingModule({
        imports: [component],
        providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([]), ChecklistPage]
    });
    TestBed.inject(SessionStore).open('token', sessionUser(seed.role ?? 'USER', { username: seed.username ?? 'erin' }));
    useEnglish();
    const page = TestBed.inject(ChecklistPage);
    page.id.set(PROJECT_ID);
    page.loading.set(false);
    page.view.set(seed.view ?? null);
    page.revisions.set(seed.revisions ?? (seed.view ? [seed.view.checklist, SIGNED_REVISION] : []));
    page.measurements.set(seed.measurements ?? null);
    page.offered.set(seed.offered ?? []);
    const fixture = TestBed.createComponent(component);
    for (const [name, value] of Object.entries(inputs)) fixture.componentRef.setInput(name, value);
    fixture.detectChanges();
    return {
        fixture,
        page,
        http: TestBed.inject(HttpTestingController),
        dom: () => fixture.nativeElement as HTMLElement
    };
}

export const BASE = `/api/v1/projects/${PROJECT_ID}/checklists`;

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
