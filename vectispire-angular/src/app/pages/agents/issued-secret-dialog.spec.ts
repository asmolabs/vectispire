import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { mountOnAgents } from './agents-page.testing';
import { IssuedSecretDialog } from './issued-secret-dialog';

/** The agent's secret, shown once and forgotten by the screen on the confirmation. */
describe('the issued secret dialog', () => {
    afterEach(() => TestBed.resetTestingModule());

    it('shows the secret, then forgets it', () => {
        const { page, fixture } = mountOnAgents(IssuedSecretDialog);
        page.issuedSecret.set('SECRET-123');
        page.secretVisible.set(true);
        fixture.detectChanges();
        expect(document.body.textContent).toContain('SECRET-123');

        fixture.componentInstance.dismissSecret();
        expect(page.issuedSecret()).toBeNull();
        expect(page.secretVisible()).toBe(false);
    });
});
