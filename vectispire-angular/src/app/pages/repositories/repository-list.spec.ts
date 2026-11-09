import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import type { MonitoredRepository } from '@/app/core/api.models';
import { useFrench } from '@/app/core/testing/english';
import { repositorySummary } from '@/app/core/testing/targets.fixtures';
import { RepositoryList } from './repository-list';
import { mountOnRepositories, namedButton } from './repositories-page.testing';

/**
 * The list of repositories, on its own: each card's schedule in words, following the language, a scan
 * queued from a card, and the edit handed to the page — offered to an administrator only.
 */
describe('the list of monitored repositories', () => {
    afterEach(() => TestBed.resetTestingModule());

    const manual = repositorySummary(5, { displayName: 'payments-api', scanManualOnly: true });

    it('says each schedule, and follows the language', () => {
        const { dom, fixture } = mountOnRepositories(RepositoryList, { repositories: [manual] });
        expect(dom().textContent).toContain('manual only');
        useFrench();
        fixture.detectChanges();
        expect(dom().textContent).toContain('manuel uniquement');
    });

    it('queues a scan from a card, and hands an edit to the page', () => {
        const { dom, fixture, http } = mountOnRepositories(RepositoryList, { repositories: [manual] });
        const edited: MonitoredRepository[] = [];
        fixture.componentInstance.edit.subscribe((repository) => edited.push(repository));
        namedButton(dom(), `Edit ${manual.url}`).click();
        expect(edited).toEqual([manual]);
        namedButton(dom(), `Run a scan of ${manual.url}`).click();
        http.expectOne((call) => call.method === 'POST' && call.url === '/api/v1/repositories/5/scan');
    });

    it('offers a reader no write', () => {
        const { dom } = mountOnRepositories(RepositoryList, { repositories: [manual], role: 'USER' });
        expect(
            Array.from(dom().querySelectorAll('button')).some((b) => b.getAttribute('aria-label')?.startsWith('Edit'))
        ).toBe(false);
    });
});
