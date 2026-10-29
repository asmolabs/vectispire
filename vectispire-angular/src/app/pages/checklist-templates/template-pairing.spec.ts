import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { CONFIRMED_PREVIEW, VERSION } from '@/app/core/testing/checklists.fixtures';
import { buttonIn, mountOnTemplates, textOf, VERSION_URL } from './templates-page.testing';
import { TemplatePairing } from './template-pairing';

/**
 * The pairing with the previous version, on its own: each fate counted and in words, the pair form
 * offered on a draft when an added and a removed item exist, and a pair sent with those made before.
 */
describe('the pairing of a checklist template', () => {
    afterEach(() => TestBed.resetTestingModule());

    it('counts each fate and states it on its row', () => {
        const { dom } = mountOnTemplates(TemplatePairing, { preview: CONFIRMED_PREVIEW, version: VERSION });
        expect(
            Array.from(dom().querySelectorAll('[data-testid="pairing-counts"] p-tag')).map((tag) =>
                tag.textContent?.trim()
            )
        ).toEqual(['1 unchanged', '1 changed', '1 added', '1 removed']);
        expect(textOf(dom(), '[data-testid="change-added"] p-tag')).toBe('Added');
    });

    it('pairs an added item with a removed one, keeping the pairs made before', () => {
        const earlier = { added: 'text:a', removed: 'text:b' };
        const { dom, fixture, http, page } = mountOnTemplates(TemplatePairing, {
            preview: CONFIRMED_PREVIEW,
            version: { ...VERSION, pairs: [earlier] }
        });
        expect(dom().querySelector('[data-testid="pair-form"]')).not.toBeNull();
        page.pairAdded.set('text:secrets are rotated every ninety days');
        page.pairRemoved.set('text:secrets are rotated yearly');
        fixture.detectChanges();
        buttonIn(dom(), 'pair-items').click();

        const sent = http.expectOne((call) => call.method === 'PUT' && call.url === `${VERSION_URL}/pairs`);
        expect(sent.request.body).toEqual({
            pairs: [
                earlier,
                { added: 'text:secrets are rotated every ninety days', removed: 'text:secrets are rotated yearly' }
            ]
        });
    });

    it('offers no pair form to a reader', () => {
        const { dom } = mountOnTemplates(TemplatePairing, {
            preview: CONFIRMED_PREVIEW,
            version: VERSION,
            role: 'AUDITOR'
        });
        expect(dom().querySelector('[data-testid="pair-form"]')).toBeNull();
    });
});
