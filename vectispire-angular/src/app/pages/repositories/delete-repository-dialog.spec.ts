import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { repositorySummary } from '@/app/core/testing/targets.fixtures';
import { DeleteRepositoryDialog } from './delete-repository-dialog';
import { mountOnRepositories, namedButton } from './repositories-page.testing';

/** Removing a repository, on its own: confirmed, deleted, the list read again — and a failure said. */
describe('removing a monitored repository', () => {
    afterEach(() => TestBed.resetTestingModule());

    const repository = repositorySummary(5);

    it('deletes the repository confirmed, and reads the list again', () => {
        const { fixture, http, page } = mountOnRepositories(DeleteRepositoryDialog, { repositories: [repository] });
        page.askDelete(repository);
        fixture.detectChanges();
        namedButton(document, 'Delete').click();
        http.expectOne((call) => call.method === 'DELETE' && call.url === '/api/v1/repositories/5').flush(null);
        expect(page.deleteVisible()).toBe(false);
        http.expectOne('/api/v1/repositories');
    });

    it('says the deletion failed', () => {
        const { fixture, http, page } = mountOnRepositories(DeleteRepositoryDialog, { repositories: [repository] });
        page.askDelete(repository);
        fixture.detectChanges();
        namedButton(document, 'Delete').click();
        http.expectOne('/api/v1/repositories/5').flush(null, { status: 500, statusText: 'Server Error' });
        expect(page.error()).toBe('The deletion failed.');
    });
});
