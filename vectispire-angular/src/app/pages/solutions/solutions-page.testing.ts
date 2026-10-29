import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { Type } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import type { SolutionTree } from '@/app/core/api.models';
import { SessionStore } from '@/app/core/session.store';
import { useEnglish } from '@/app/core/testing/english';
import { sessionUser } from '@/app/core/testing/session.fixtures';
import { SOLUTION_TREE } from '@/app/core/testing/solutions.fixtures';
import { SolutionsPage } from './solutions-page';

/**
 * One component of the solutions screen, mounted on its own over a `SolutionsPage` that has read the
 * tree — answered here, so the requests a spec sees are the component's. The page's own suite reads
 * the same parts through the routes.
 */
export function mountOnSolutions<T>(
    component: Type<T>,
    seed: { role?: string; tree?: SolutionTree; inputs?: Record<string, unknown> } = {}
): { fixture: ComponentFixture<T>; page: SolutionsPage; http: HttpTestingController; dom: () => HTMLElement } {
    TestBed.configureTestingModule({
        imports: [component],
        providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([]), SolutionsPage]
    });
    TestBed.inject(SessionStore).open('token', sessionUser(seed.role ?? 'ADMIN'));
    useEnglish();
    const http = TestBed.inject(HttpTestingController);
    const page = TestBed.inject(SolutionsPage);
    http.expectOne('/api/v1/solutions').flush(seed.tree ?? SOLUTION_TREE);
    const fixture = TestBed.createComponent(component);
    for (const [name, value] of Object.entries(seed.inputs ?? {})) fixture.componentRef.setInput(name, value);
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
