import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import type { ScansApi } from '@/app/core/api/scans.api';
import { asSchemaList, type AnswerOf } from '@/app/core/testing/contract';
import { repositorySummary } from '@/app/core/testing/targets.fixtures';
import { ImportsDialog } from './imports-dialog';
import { mountOnRepositories } from './repositories-page.testing';

/**
 * The repositories screen's state, on its own: a scan queued said as queued, every repository queued
 * at once, and a background refresh leaving an action's error in place.
 */
describe('the state of the repositories screen', () => {
    afterEach(() => TestBed.resetTestingModule());

    const one = repositorySummary(5, { displayName: 'payments-api' });
    const two = repositorySummary(6);

    it('says a scan is queued, not run, and reads the list again', () => {
        const { page, http } = mountOnRepositories(ImportsDialog, { repositories: [one] });
        page.triggerScan(one);
        http.expectOne('/api/v1/repositories/5/scan').flush({ id: 1, status: 'pending' } satisfies AnswerOf<
            ScansApi['triggerRepositoryScan']
        >);
        expect(page.notice()).toBe('Scan queued for payments-api. It will start as soon as a worker is available.');
        http.expectOne('/api/v1/repositories');
    });

    it('keeps an action error through a background refresh', () => {
        const { page, http } = mountOnRepositories(ImportsDialog, { repositories: [one, two] });
        page.error.set('A scan is already queued.');
        page.reload(true);
        http.expectOne('/api/v1/repositories').flush(asSchemaList('RepositorySummary', [one, two]));
        expect(page.error()).toBe('A scan is already queued.');
    });
});
