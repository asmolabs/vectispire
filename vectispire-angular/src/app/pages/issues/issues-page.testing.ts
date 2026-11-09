import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { Type } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import type { Issue } from '@/app/core/api.models';
import { SessionStore } from '@/app/core/session.store';
import { asSchema } from '@/app/core/testing/contract';
import { useEnglish } from '@/app/core/testing/english';
import { aiAdvisorStatus } from '@/app/core/testing/intel.fixtures';
import { sessionUser } from '@/app/core/testing/session.fixtures';
import { IssuesPage } from './issues-page';

/** What a part of the issues screen is mounted over: an account, and the page of issues the server sent. */
export interface Seed {
    role?: string;
    issues?: Issue[];
    total?: number;
    ai?: boolean;
}

/**
 * One component of the issues screen, mounted on its own over an `IssuesPage` that has made its first
 * reads — the targets, the advisor's status and the first page — so the requests a spec sees are the
 * component's. The page's own suite reads the same parts through the routes and the URL.
 */
export function mountOnIssues<T>(
    component: Type<T>,
    seed: Seed = {}
): { fixture: ComponentFixture<T>; page: IssuesPage; http: HttpTestingController; dom: () => HTMLElement } {
    TestBed.configureTestingModule({
        imports: [component],
        providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([]), IssuesPage]
    });
    TestBed.inject(SessionStore).open('token', sessionUser(seed.role ?? 'ADMIN'));
    useEnglish();
    const http = TestBed.inject(HttpTestingController);
    const page = TestBed.inject(IssuesPage);
    http.expectOne((call) => call.url === '/api/v1/repositories').flush([]);
    http.expectOne((call) => call.url === '/api/v1/containers').flush([]);
    http.expectOne((call) => call.url === '/api/v1/ai-advisor/status').flush(aiAdvisorStatus(seed.ai ?? true));
    const issues = seed.issues ?? [];
    http.expectOne((call) => call.url === '/api/v1/issues').flush(
        asSchema('IssuePage', { items: issues, total: seed.total ?? issues.length, limit: 50, offset: 0 })
    );
    const fixture = TestBed.createComponent(component);
    fixture.detectChanges();
    return { fixture, page, http, dom: () => fixture.nativeElement as HTMLElement };
}

export const textOf = (dom: HTMLElement, selector: string): string =>
    dom.querySelector(selector)?.textContent?.replace(/\s+/g, ' ').trim() ?? '';

/** A button by its accessible name or its text. */
export function namedButton(dom: HTMLElement, name: string): HTMLButtonElement {
    const found = Array.from(dom.querySelectorAll('button')).find(
        (button) => button.getAttribute('aria-label') === name || button.textContent?.trim() === name
    );
    if (!found) throw new Error(`no button ${name}`);
    return found;
}
