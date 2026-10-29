import { HttpErrorResponse } from '@angular/common/http';
import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { CONFIRMED_PREVIEW, conflict, SECRETS_RULE, VERSION } from '@/app/core/testing/checklists.fixtures';
import { mountOnTemplates, VERSION_URL } from './templates-page.testing';
import { TemplateVersionPanel } from './template-version-panel';

/**
 * The templates screen's state on its own: a refusal explained from its cause — under four-eyes, by the
 * act refused — and a write's answer adopted, the edits not sent dropped and everything read again.
 */
describe('the state of the checklist templates screen', () => {
    afterEach(() => TestBed.resetTestingModule());

    const refused = (token: string) => new HttpErrorResponse({ status: 409, error: conflict(token) });

    it('names the act a four-eyes refusal withholds, and offers no reload for it', () => {
        const { page } = mountOnTemplates(TemplateVersionPanel, { preview: CONFIRMED_PREVIEW, version: VERSION });
        expect(page.refuse(refused('checklist-four-eyes'), 'retire', 4)).toBe(true);
        expect(page.refusal()?.message).toContain('a second person must retire it');
        expect(page.refusal()?.reload).toBe(false);
        page.refuse(refused('checklist-four-eyes'), 'publish', 4);
        expect(page.refusal()?.message).toContain('a second person must publish it');
    });

    it('leaves a failure that names no cause to the caller', () => {
        const { page } = mountOnTemplates(TemplateVersionPanel, { preview: CONFIRMED_PREVIEW, version: VERSION });
        expect(page.refuse(new HttpErrorResponse({ status: 500 }), 'edit', 4)).toBe(false);
        expect(page.refusal()).toBeNull();
    });

    it("adopts a write's answer: the edits on screen dropped, the preview, version and row read again", () => {
        const { page, http } = mountOnTemplates(TemplateVersionPanel, { preview: CONFIRMED_PREVIEW, version: VERSION });
        page.evidenceEdits.set({ 'text:x': { kind: 'file', months: 3 } });
        page.ruleEdits.set({ 'text:x': SECRETS_RULE });
        const after = { ...VERSION, version: { ...VERSION.version, revision: 5 } };

        page.afterWrite(after);

        expect(page.version()).toBe(after);
        expect(page.shown()?.revision).toBe(5);
        expect(page.evidenceEdits()).toEqual({});
        expect(page.ruleEdits()).toEqual({});
        http.expectOne((call) => call.url === `${VERSION_URL}/preview`);
        http.expectOne(VERSION_URL);
        http.expectOne('/api/v1/checklist-templates/release');
    });
});
