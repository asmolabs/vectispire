import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { mountOnAgents } from './agents-page.testing';
import { SigningKeyDialog } from './signing-key-dialog';

/** The private half of a signing key, shown once with where it goes, and forgotten on the confirmation. */
describe('the signing key dialog', () => {
    afterEach(() => TestBed.resetTestingModule());

    it('shows the key and the variable it goes in, then forgets it', () => {
        const { page, fixture } = mountOnAgents(SigningKeyDialog);
        page.issuedSigningKey.set('PRIVATE-KEY');
        page.signingKeyVisible.set(true);
        fixture.detectChanges();
        expect(document.body.textContent).toContain('PRIVATE-KEY');
        expect(document.body.textContent).toContain('VECTISPIRE_AGENT_SIGNING_KEY');

        fixture.componentInstance.dismissSigningKey();
        expect(page.issuedSigningKey()).toBeNull();
        expect(page.signingKeyVisible()).toBe(false);
    });
});
