import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { Type } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import type { GitTokenSummary, MonitoredRepository } from '@/app/core/api.models';
import { SessionStore } from '@/app/core/session.store';
import { asSchemaList } from '@/app/core/testing/contract';
import { useEnglish } from '@/app/core/testing/english';
import { sessionUser } from '@/app/core/testing/session.fixtures';
import { RepositoriesPage } from './repositories-page';

/** What a part of the repositories screen is mounted over: an account, the list and the credentials. */
export interface Seed {
    role?: string;
    repositories?: MonitoredRepository[];
    tokens?: GitTokenSummary[];
}

/**
 * One component of the repositories screen, mounted on its own over a `RepositoriesPage` that has made
 * its first reads — the list, the keys, the tokens and, for an administrator, the default interval —
 * so the requests a spec sees are the component's.
 */
export function mountOnRepositories<T>(
    component: Type<T>,
    seed: Seed = {}
): { fixture: ComponentFixture<T>; page: RepositoriesPage; http: HttpTestingController; dom: () => HTMLElement } {
    TestBed.configureTestingModule({
        imports: [component],
        providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([]), RepositoriesPage]
    });
    TestBed.inject(SessionStore).open('token', sessionUser(seed.role ?? 'ADMIN'));
    useEnglish();
    const http = TestBed.inject(HttpTestingController);
    const page = TestBed.inject(RepositoriesPage);
    http.expectOne('/api/v1/repositories').flush(asSchemaList('RepositorySummary', seed.repositories ?? []));
    http.expectOne('/api/v1/ssh-keys').flush([]);
    http.expectOne('/api/v1/git-tokens').flush(asSchemaList('GitTokenSummary', seed.tokens ?? []));
    // The default interval, read for an administrator's dialog; its answer is not this suite's concern.
    for (const settings of http.match('/api/v1/settings')) settings.flush({ settings: [] });
    const fixture = TestBed.createComponent(component);
    fixture.detectChanges();
    return { fixture, page, http, dom: () => fixture.nativeElement as HTMLElement };
}

export const textOf = (dom: Element | Document, selector: string): string =>
    dom.querySelector(selector)?.textContent?.replace(/\s+/g, ' ').trim() ?? '';

/** A button by its accessible name or its text, in the page or in a dialog appended to the body. */
export function namedButton(dom: Element | Document, name: string): HTMLButtonElement {
    const found = Array.from(dom.querySelectorAll('button')).find(
        (button) => button.getAttribute('aria-label') === name || button.textContent?.trim() === name
    );
    if (!found) throw new Error(`no button ${name}`);
    return found;
}
