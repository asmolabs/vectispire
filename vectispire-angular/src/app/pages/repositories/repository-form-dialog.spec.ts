import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import type { NewRepository } from '@/app/core/api.models';
import { repositorySummary } from '@/app/core/testing/targets.fixtures';
import { RepositoryFormDialog } from './repository-form-dialog';
import { mountOnRepositories } from './repositories-page.testing';

/**
 * The repository form, on its own: a form whose URL is required, the credentials its transport allows,
 * a submit that sends what it shows, and a target already filed said by its name.
 */
describe('the repository form', () => {
    afterEach(() => TestBed.resetTestingModule());

    const existing = repositorySummary(5, { displayName: 'payments-api', url: 'https://example.org/payments.git' });
    const form = () => document.querySelector<HTMLFormElement>('form#repository-form')!;

    it('is a form whose URL is required', () => {
        const { fixture } = mountOnRepositories(RepositoryFormDialog);
        fixture.componentInstance.openForm();
        fixture.detectChanges();
        expect(form()).not.toBeNull();
        expect(document.querySelector<HTMLInputElement>('#url')!.required).toBe(true);
    });

    it('offers no SSH key to an https:// clone, and drops one chosen before the URL changed', () => {
        const { fixture } = mountOnRepositories(RepositoryFormDialog);
        const dialog = fixture.componentInstance;
        dialog.openForm();
        dialog.form.credentialKind = 'ssh';
        dialog.form.url = 'https://example.org/app.git';
        dialog.onUrlChange();
        expect(dialog.credentialKinds().map((kind) => kind.value)).toEqual(['none', 'https']);
        expect(dialog.form.credentialKind).toBe('none');
    });

    it('sends what it shows on a submit, and names a target already filed', () => {
        const { fixture, http } = mountOnRepositories(RepositoryFormDialog, { repositories: [existing] });
        const dialog = fixture.componentInstance;
        dialog.openForm();
        dialog.form.url = ' https://example.org/payments.git ';
        fixture.detectChanges();
        form().dispatchEvent(new Event('submit'));

        const sent = http.expectOne((call) => call.method === 'POST' && call.url === '/api/v1/repositories');
        expect((sent.request.body as NewRepository).url).toBe('https://example.org/payments.git');
        sent.flush(
            {
                type: 'urn:vectispire:problem:target-already-registered',
                title: 'Conflict',
                status: 409,
                detail: 'English.',
                existingRepositoryId: 5
            },
            { status: 409, statusText: 'Conflict' }
        );
        expect(dialog.formError()).toBe(
            'This repository is already a target, on the same branch and sub-path: payments-api. Edit that one, or choose another branch or sub-path.'
        );
        expect(dialog.formVisible()).toBe(true);
    });
});
