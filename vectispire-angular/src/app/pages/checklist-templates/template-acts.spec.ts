import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import type { ChecklistPreview } from '@/app/core/api.models';
import { CONFIRMED_PREVIEW, PUBLISHED, VERSION } from '@/app/core/testing/checklists.fixtures';
import { asSchema } from '@/app/core/testing/contract';
import { buttonIn, mountOnTemplates, textOf, VERSION_URL } from './templates-page.testing';
import { TemplateActs } from './template-acts';

/**
 * The acts on a version, on its own: a draft published only once confirmed, naming the revision on
 * screen; a draft set aside said so; and the publication withheld from an author while four-eyes is on.
 */
describe('the acts on a checklist template', () => {
    afterEach(() => TestBed.resetTestingModule());

    it('publishes the revision on screen once confirmed', () => {
        const { dom, fixture, http, page } = mountOnTemplates(TemplateActs, {
            preview: CONFIRMED_PREVIEW,
            version: VERSION
        });
        buttonIn(dom(), 'publish-version').click();
        fixture.detectChanges();
        expect(textOf(dom(), '[data-testid="confirm-act"]')).toContain('Publish revision 4, as shown on this page?');
        buttonIn(dom(), 'confirm-act').click();

        const sent = http.expectOne((call) => call.method === 'POST' && call.url === `${VERSION_URL}/publish`);
        expect(sent.request.body).toEqual({ revision: CONFIRMED_PREVIEW.version.revision });
        sent.flush(
            asSchema('ChecklistVersionView', { ...VERSION, version: { ...VERSION.version, status: 'published' } })
        );
        expect(page.notice()).toBe('Version 2 published.');
    });

    it('calls retiring a draft setting it aside', () => {
        const { dom, fixture, http, page } = mountOnTemplates(TemplateActs, {
            preview: CONFIRMED_PREVIEW,
            version: VERSION
        });
        buttonIn(dom(), 'retire-version').click();
        fixture.detectChanges();
        expect(textOf(dom(), '[data-testid="confirm-act"]')).toContain(
            'Set this draft aside? It will never be published.'
        );
        buttonIn(dom(), 'confirm-act').click();
        http.expectOne((call) => call.method === 'POST' && call.url === `${VERSION_URL}/retire`).flush(VERSION);
        expect(page.notice()).toBe('Draft 2 set aside.');
    });

    it("withholds publishing from the draft's author while four-eyes is not known to be off", () => {
        const { dom } = mountOnTemplates(TemplateActs, {
            preview: CONFIRMED_PREVIEW,
            version: VERSION,
            username: 'Alice'
        });
        expect(buttonIn(dom(), 'publish-version').disabled).toBe(true);
        expect(dom().querySelector('[data-testid="publish-four-eyes"]')).not.toBeNull();
    });

    it('offers to derive from a published version rather than publish it', () => {
        const published: ChecklistPreview = { ...CONFIRMED_PREVIEW, version: PUBLISHED };
        const { dom } = mountOnTemplates(TemplateActs, { preview: published, version: VERSION });
        expect(dom().querySelector('#derive-version')).not.toBeNull();
        expect(dom().querySelector('#publish-version')).toBeNull();
    });
});
