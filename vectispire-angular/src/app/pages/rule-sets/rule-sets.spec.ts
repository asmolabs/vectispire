import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { RuleSets } from './rule-sets';
import { asSchema } from '@/app/core/testing/contract';

/**
 * What the upstream catalogue's preview says before it is imported.
 *
 * **A grey square on the OWASP grid said two opposite things.** It is set when no installed rule
 * declares the category — which can mean "no scanner here knows how to look there", or "the rules
 * that do were never imported". Telling them apart meant importing first and looking afterwards,
 * the reverse of the order an operator wants: they choose what they import.
 *
 * The count is read from the rules themselves, by their own `metadata.owasp`, in the same pass as
 * the count by language.
 */
describe('the catalogue preview', () => {
    let fixture: ComponentFixture<RuleSets>;
    let http: HttpTestingController;

    const preview = (categories: Record<string, number>) =>
        asSchema('CataloguePreview', {
            upstream: 'opengrep/opengrep-rules',
            commit: '1c7e0f3a9b2d4e5f6a7b8c9d0e1f2a3b4c5d6e7f',
            licenceName: 'LGPL-2.1 with Commons Clause',
            licence: 'the full text',
            licence_sha256: 'abc123',
            languages: { java: 412, python: 388 },
            categories
        });

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [RuleSets],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        fixture = TestBed.createComponent(RuleSets);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();

        // What the screen asks for on its own at start-up.
        for (const request of http.match(() => true)) {
            request.flush(
                request.request.url.endsWith('/coverage') ? { state: 'COVERED', ruleFiles: 0 } : { ruleSets: [] }
            );
        }
        fixture.detectChanges();
    }, 20_000);

    function readCatalogue(categories: Record<string, number>): void {
        fixture.componentInstance.readCatalogue();
        http.expectOne('/api/v1/rule-sets/catalogue').flush(preview(categories));
        fixture.detectChanges();
    }

    it('names the Top 10 categories these rules declare, with their counts', () => {
        readCatalogue({ A03: 128, A01: 44, A10: 7 });

        // Sorted: two readings of the same catalogue must present the same list, and the order of
        // a JSON map is no guarantee.
        expect(fixture.componentInstance.categoriesOf(fixture.componentInstance.catalogue()!)).toEqual([
            { id: 'A01', count: 44 },
            { id: 'A03', count: 128 },
            { id: 'A10', count: 7 }
        ]);

        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('A01 (44)');
        expect(text).toContain('A03 (128)');
    });

    /**
     * **The empty case is an answer, not a failure to display.** A catalogue in which no rule
     * declares a category will move no square of the grid — saying so avoids the import somebody
     * would make hoping otherwise.
     */
    it('says a catalogue that declares nothing will move no square', () => {
        readCatalogue({});

        expect(fixture.componentInstance.categoriesOf(fixture.componentInstance.catalogue()!)).toEqual([]);
        // The key rather than the sentence, since the sentence now has two of them and this
        // harness renders keys unresolved. It is also the better assertion: a rewording of the
        // English does not break it, and a screen that stops rendering the empty branch does.
        expect(fixture.nativeElement.textContent as string).toContain('rule_sets.owasp_none');
    });
});
