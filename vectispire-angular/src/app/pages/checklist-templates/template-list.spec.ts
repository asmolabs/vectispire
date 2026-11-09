import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { DRAFT, PUBLISHED, TEMPLATE } from '@/app/core/testing/checklists.fixtures';
import { useFrench } from '@/app/core/testing/english';
import { buttonIn, mountOnTemplates, textOf, VERSION_URL } from './templates-page.testing';
import { TemplateList } from './template-list';

/**
 * The list of templates, on its own: each version's status in words, the one open marked, no new
 * version offered beside a draft, and a version opened on request.
 */
describe('the list of checklist templates', () => {
    afterEach(() => TestBed.resetTestingModule());

    const newVersion = (dom: HTMLElement) =>
        dom.querySelector<HTMLButtonElement>('[data-testid="new-version-release"] button')!;
    const row = (ordinal: number) => `[data-testid="version-release-${ordinal}"]`;

    it('states each version, and offers no new version while the template has a draft', () => {
        const { dom } = mountOnTemplates(TemplateList, { templates: [TEMPLATE] });
        expect(textOf(dom(), `${row(PUBLISHED.ordinal)} p-tag`)).toBe('Published');
        expect(textOf(dom(), `${row(DRAFT.ordinal)} p-tag`)).toBe('Draft');
        expect(newVersion(dom()).disabled).toBe(true);
    });

    it('offers a new version once the draft is gone, and hands the import form its slug', () => {
        const { dom, fixture, page } = mountOnTemplates(TemplateList, {
            templates: [{ ...TEMPLATE, versions: [PUBLISHED] }]
        });
        newVersion(dom()).click();
        fixture.detectChanges();
        expect(page.uploadSlug()).toBe('release');
    });

    it('opens a version on request, and marks it in the list', () => {
        const { dom, fixture, http } = mountOnTemplates(TemplateList, { templates: [TEMPLATE] });
        buttonIn(dom(), 'Open version 2 of release').click();
        fixture.detectChanges();
        http.expectOne((call) => call.url === `${VERSION_URL}/preview`);
        http.expectOne(VERSION_URL);
        expect(dom().querySelector(row(DRAFT.ordinal))!.classList.contains('font-semibold')).toBe(true);
        expect(dom().querySelector(row(PUBLISHED.ordinal))!.classList.contains('font-semibold')).toBe(false);
    });

    it('rewrites the statuses when the language changes', () => {
        const { dom, fixture } = mountOnTemplates(TemplateList, { templates: [TEMPLATE] });
        useFrench();
        fixture.detectChanges();
        expect(textOf(dom(), `${row(DRAFT.ordinal)} p-tag`)).toBe('Brouillon');
    });
});
