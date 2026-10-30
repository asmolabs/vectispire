import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { Type } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import type {
    AgentActivitySummary,
    AgentSummary,
    UnroutableLabel,
    UnservedCredentialedScans
} from '@/app/core/api.models';
import { SessionStore } from '@/app/core/session.store';
import { NO_CREDENTIALED_BACKLOG } from '@/app/core/testing/agents.fixtures';
import { useEnglish } from '@/app/core/testing/english';
import { sessionUser } from '@/app/core/testing/session.fixtures';
import { AgentsPage } from './agents-page';

export interface AgentsSeed {
    role?: string;
    agents?: AgentSummary[];
    /** Absent: the activity read fails, so no polling timer starts. */
    activity?: AgentActivitySummary;
    backlog?: UnservedCredentialedScans;
    unroutable?: UnroutableLabel[];
}

/** Answers the four reads a reload makes, as seeded. */
export function answerReload(http: HttpTestingController, seed: AgentsSeed = {}): void {
    for (const request of http.match((r) => r.method === 'GET')) {
        const url = request.request.url;
        if (url === '/api/v1/admin/agents') request.flush(seed.agents ?? []);
        else if (url.endsWith('/activity')) {
            if (seed.activity) request.flush(seed.activity);
            else request.flush(null, { status: 500, statusText: 'unavailable' });
        } else if (url.endsWith('/credentialed-backlog')) request.flush(seed.backlog ?? NO_CREDENTIALED_BACKLOG);
        else request.flush(seed.unroutable ?? []);
    }
}

/**
 * One component of the agents screen, mounted on its own over an `AgentsPage` that has read the fleet
 * — answered here, so the requests a spec sees are the component's. The screen's own suite reads the
 * same parts through the shell.
 */
export function mountOnAgents<T>(
    component: Type<T>,
    seed: AgentsSeed = {}
): { fixture: ComponentFixture<T>; page: AgentsPage; http: HttpTestingController; dom: () => HTMLElement } {
    TestBed.configureTestingModule({
        imports: [component],
        providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([]), AgentsPage]
    });
    TestBed.inject(SessionStore).user.set(sessionUser(seed.role ?? 'ADMIN'));
    useEnglish();
    const http = TestBed.inject(HttpTestingController);
    const page = TestBed.inject(AgentsPage);
    page.reload();
    answerReload(http, seed);
    const fixture = TestBed.createComponent(component);
    fixture.detectChanges();
    return { fixture, page, http, dom: () => fixture.nativeElement as HTMLElement };
}

export const textOf = (dom: Element | Document, selector: string): string =>
    dom.querySelector(selector)?.textContent?.replace(/\s+/g, ' ').trim() ?? '';
