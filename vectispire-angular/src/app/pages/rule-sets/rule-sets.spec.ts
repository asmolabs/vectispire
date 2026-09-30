import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { RuleSets } from './rule-sets';
import { asSchema } from '@/app/core/testing/contract';
import { I18nService } from '@/app/core/i18n/i18n.service';

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

/**
 * A rule-set change states the loss it accepts.
 *
 * **The server refuses a change that resolves open issues unless `acceptLosing` equals the count it
 * re-reads when it activates** (409 `rule-set-activation-loses-issues`). The screen's part is to send
 * the number the operator had in front of them — not a flag, not a retried guess — and, when the
 * backlog moved since the preview, to show the server's number and wait for a second click.
 * Asserted through the requests and the DOM: a component method that sends the right body proves
 * nothing if the button calls another one.
 */
describe('a rule-set change', () => {
    let fixture: ComponentFixture<RuleSets>;
    let http: HttpTestingController;

    const LOSES = 'urn:vectispire:problem:rule-set-activation-loses-issues';

    const summary = (id: number, name: string, isActive: boolean) =>
        asSchema('RuleSetSummary', {
            id,
            name,
            contentHash: 'a1b2c3d4e5f6a7b8',
            sizeBytes: '2048',
            ruleCount: 12,
            fileCount: 3,
            uploadedAt: '2026-09-01T10:00:00Z',
            uploadedBy: 'ciso',
            isActive,
            activationNote: null
        });

    const impact = (affectedIssues: number, losingIssues: string[]) =>
        asSchema('TriageImpact', { addedRules: 4, removedRules: 2, affectedIssues, losingIssues });

    const losesIssues = (affectedIssues: number, losingIssues: string[]) =>
        asSchema('RuleSetLosesIssuesProblem', {
            type: LOSES,
            title: 'Conflict',
            status: 409,
            detail: `${affectedIssues} open issues would resolve`,
            affectedIssues,
            losingIssues
        });

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [RuleSets],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        // Only the sentence under test is translated, so that its count is visible in the DOM.
        TestBed.inject(I18nService).translations.set({
            rule_sets: { backlog_changed: 'Backlog changed: {{count}} would now resolve.' }
        });
        fixture = TestBed.createComponent(RuleSets);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();

        for (const request of http.match(() => true)) {
            request.flush(
                request.request.url.endsWith('/coverage')
                    ? { state: 'COVERED', ruleFiles: 0 }
                    : { ruleSets: [summary(1, 'incoming', false), summary(2, 'current', true)] }
            );
        }
        fixture.detectChanges();
    }, 20_000);

    function click(label: string): void {
        const button = [...(fixture.nativeElement as HTMLElement).querySelectorAll('button')].find(
            (candidate) => candidate.textContent?.trim() === label
        );
        expect(button, `a button labelled ${label}`).toBeTruthy();
        button!.click();
        fixture.detectChanges();
    }

    function previewActivation(affected: number, losing: string[] = []): void {
        click('rule_sets.review_btn');
        http.expectOne('/api/v1/rule-sets/1/impact').flush(impact(affected, losing));
        fixture.detectChanges();
    }

    const text = () => (fixture.nativeElement as HTMLElement).textContent ?? '';
    const reload = () => http.expectOne('/api/v1/rule-sets').flush({ ruleSets: [] });

    it('activates with the count the preview showed', () => {
        previewActivation(3, ['java.sqli']);
        click('rule_sets.activate_btn');

        const request = http.expectOne('/api/v1/rule-sets/1/activate');
        expect(request.request.method).toBe('POST');
        expect(request.request.body).toMatchObject({ acceptLosing: 3 });
        request.flush({ id: 1, contentHash: 'a1b2' });
        reload();
    });

    it('sends no acceptance when the preview loses nothing', () => {
        previewActivation(0);
        click('rule_sets.activate_btn');

        const request = http.expectOne('/api/v1/rule-sets/1/activate');
        expect(Object.keys(request.request.body as object)).not.toContain('acceptLosing');
        request.flush({ id: 1, contentHash: 'a1b2' });
        reload();
    });

    it('shows the count the backlog moved to, and accepts that one only on a second click', () => {
        previewActivation(3, ['java.sqli']);
        click('rule_sets.activate_btn');
        http.expectOne('/api/v1/rule-sets/1/activate').flush(losesIssues(5, ['java.sqli', 'java.xss']), {
            status: 409,
            statusText: 'Conflict'
        });
        fixture.detectChanges();

        expect(text()).toContain('Backlog changed: 5 would now resolve.');
        expect(text()).toContain('java.xss');
        // Never retried on the operator's behalf: the number is theirs to read.
        http.expectNone('/api/v1/rule-sets/1/activate');

        click('rule_sets.activate_btn');
        const again = http.expectOne('/api/v1/rule-sets/1/activate');
        expect(again.request.body).toMatchObject({ acceptLosing: 5 });
        again.flush({ id: 1, contentHash: 'a1b2' });
        reload();
        fixture.detectChanges();
        expect(text()).not.toContain('Backlog changed');
    });

    it('shows any other refusal as the server words it, without asking for a new count', () => {
        previewActivation(3, ['java.sqli']);
        click('rule_sets.activate_btn');
        http.expectOne('/api/v1/rule-sets/1/activate').flush(
            { type: 'about:blank', title: 'Conflict', status: 409, detail: 'Another activation is under way.' },
            { status: 409, statusText: 'Conflict' }
        );
        fixture.detectChanges();

        expect(text()).toContain('Another activation is under way.');
        expect(text()).not.toContain('Backlog changed');
    });

    it('previews a deactivation and guards it the same way', () => {
        click('rule_sets.deactivate_btn');
        // The first click opens the preview; it deactivates nothing.
        http.expectNone('/api/v1/rule-sets/deactivate');
        http.expectOne('/api/v1/rule-sets/deactivate/impact').flush(impact(4, ['java.sqli']));
        fixture.detectChanges();

        click('rule_sets.deactivate_confirm_btn');
        const first = http.expectOne('/api/v1/rule-sets/deactivate');
        expect(first.request.body).toEqual({ acceptLosing: 4 });
        first.flush(losesIssues(6, ['java.sqli']), { status: 409, statusText: 'Conflict' });
        fixture.detectChanges();
        expect(text()).toContain('Backlog changed: 6 would now resolve.');

        click('rule_sets.deactivate_confirm_btn');
        const second = http.expectOne('/api/v1/rule-sets/deactivate');
        expect(second.request.body).toEqual({ acceptLosing: 6 });
        second.flush({ active: null });
        reload();
    });

    it('deactivates without an acceptance when nothing would resolve', () => {
        click('rule_sets.deactivate_btn');
        http.expectOne('/api/v1/rule-sets/deactivate/impact').flush(impact(0, []));
        fixture.detectChanges();

        click('rule_sets.deactivate_confirm_btn');
        const request = http.expectOne('/api/v1/rule-sets/deactivate');
        expect(request.request.body).toEqual({});
        request.flush({ active: null });
        reload();
    });
});
