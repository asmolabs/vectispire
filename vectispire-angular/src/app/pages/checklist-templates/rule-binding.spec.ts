import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting, TestRequest } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { afterEach, describe, expect, it } from 'vitest';
import type { ChecklistPreview, ChecklistVersion } from '@/app/core/api.models';
import { SessionStore } from '@/app/core/session.store';
import { asSchema } from '@/app/core/testing/contract';
import {
    BOUND_VERSION,
    conflict,
    CONFIRMED_PREVIEW,
    DRAFT,
    PREVIEW,
    PUBLISHED,
    SECRETS_RULE,
    TEMPLATE,
    VERSION
} from '@/app/core/testing/checklists.fixtures';
import { useEnglish } from '@/app/core/testing/english';
import { PLUGIN, SOURCE } from '@/app/core/testing/plugins.fixtures';
import { ChecklistTemplates, ruleChangesOf } from './checklist-templates';

/**
 * Binding the rule a template line is measured by (decision 0032 §6), through the DOM.
 *
 * What it must get right: the form is offered where the route accepts it — a security lead, a draft,
 * a confirmed layout — and nowhere else; the KPI's text stands beside the parameters; each kind sends
 * its own parameters and no other, refused in the reader's words where the server would refuse them;
 * and only the lines changed are sent, on the revision shown.
 */
describe('binding a rule to a template line', () => {
    let fixture: ComponentFixture<ChecklistTemplates>;
    let http: HttpTestingController;

    const TEMPLATE_URL = '/api/v1/checklist-templates';
    const VERSION_URL = `${TEMPLATE_URL}/release/versions/2`;
    const ROW_5 = 'text:service accounts hold no interactive login';
    const ROW_7 = 'text:dependencies carry no known critical vulnerability';

    afterEach(() => {
        try {
            http?.verify();
        } finally {
            TestBed.resetTestingModule();
        }
    });

    async function start(role: string, preview: ChecklistPreview = CONFIRMED_PREVIEW, version = VERSION) {
        await TestBed.configureTestingModule({
            imports: [ChecklistTemplates],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();
        TestBed.inject(SessionStore).open('token', {
            username: 'bob',
            displayName: null,
            role,
            mustChangePassword: false,
            mfaEnabled: false
        });
        useEnglish();
        fixture = TestBed.createComponent(ChecklistTemplates);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        http.expectOne(TEMPLATE_URL).flush([TEMPLATE]);
        fixture.detectChanges();
        const ordinal = preview.version.ordinal;
        button(`Open version ${ordinal} of release`).click();
        fixture.detectChanges();
        http.expectOne((call) => call.url === `${TEMPLATE_URL}/release/versions/${ordinal}/preview`).flush(preview);
        http.expectOne(`${TEMPLATE_URL}/release/versions/${ordinal}`).flush(version);
        fixture.detectChanges();
    }

    const dom = () => fixture.nativeElement as HTMLElement;
    const text = (selector: string) => dom().querySelector(selector)?.textContent?.replace(/\s+/g, ' ').trim() ?? '';
    const has = (selector: string) => dom().querySelector(selector) !== null;

    function button(idOrName: string): HTMLButtonElement {
        const host = dom().querySelector(`[id="${idOrName}"]`);
        const found =
            host?.tagName === 'BUTTON'
                ? host
                : (host?.querySelector('button') ??
                  Array.from(dom().querySelectorAll('button')).find(
                      (candidate) =>
                          candidate.getAttribute('aria-label') === idOrName ||
                          candidate.textContent?.trim() === idOrName
                  ));
        if (!found) throw new Error(`no button ${idOrName}`);
        return found as HTMLButtonElement;
    }

    function type(selector: string, value: string): void {
        const input = dom().querySelector(selector) as HTMLInputElement;
        if (!input) throw new Error(`no field ${selector}`);
        input.value = value;
        input.dispatchEvent(new Event('input'));
        fixture.detectChanges();
    }

    function choose(selector: string, label: string): void {
        const select = dom().querySelector(selector) as HTMLSelectElement;
        const index = Array.from(select.options).findIndex((option) => option.textContent?.trim() === label);
        if (index < 0) throw new Error(`no option ${label} in ${selector}`);
        select.selectedIndex = index;
        select.dispatchEvent(new Event('change'));
        fixture.detectChanges();
    }

    function check(selector: string): void {
        const input = dom().querySelector(selector) as HTMLInputElement;
        input.checked = !input.checked;
        input.dispatchEvent(new Event('change'));
        fixture.detectChanges();
    }

    async function settle(): Promise<void> {
        await fixture.whenStable();
        fixture.detectChanges();
    }

    /**
     * Opens the editor on a row; the first time, it reads the plugins and the declared sources for the
     * scopes it suggests — suggestions only, answered here with one of each.
     */
    async function edit(row: number, first = true): Promise<void> {
        button(`Rule of row ${row}`).click();
        fixture.detectChanges();
        if (first) {
            http.expectOne({ method: 'GET', url: '/api/v1/plugins' }).flush([PLUGIN]);
            http.expectOne({ method: 'GET', url: '/api/v1/sarif-sources' }).flush([
                SOURCE,
                asSchema('SarifSourceView', { ...SOURCE, id: 4, slug: 'coverage-ci', tools: [], kinds: ['coverage'] })
            ]);
        }
        await settle();
    }

    const rulesPut = () => http.expectOne((call) => call.method === 'PUT' && call.url === `${VERSION_URL}/rules`);

    /** The reads a write is followed by: the preview, the version and the template's row. */
    function answerRereads(version: ChecklistVersion): void {
        http.expectOne((call) => call.url === `${VERSION_URL}/preview`).flush({
            ...CONFIRMED_PREVIEW,
            version: version.version
        });
        http.expectOne(VERSION_URL).flush(version);
        http.expectOne(`${TEMPLATE_URL}/release`).flush(TEMPLATE);
        fixture.detectChanges();
    }

    /** Keeps the rule in the editor, then saves, and hands back the request with its body checked against the document. */
    function keepAndSave(): TestRequest {
        button('rule-keep').click();
        fixture.detectChanges();
        button('save-rules').click();
        const request = rulesPut();
        asSchema('ChecklistRulesRequest', request.request.body);
        return request;
    }

    it('binds a findings rule with the KPI beside it, sending the line changed on the revision shown', async () => {
        await start('CISO');

        expect(text('[data-testid="item-7"] [data-testid="item-rule"]')).toContain('No rule');
        expect(button('save-rules').disabled).toBe(true);
        await edit(7);

        // The template's words stand beside the parameters: the KPI is text, never parsed.
        expect(text('[data-testid="rule-beside"]')).toContain('Dependencies carry no known critical vulnerability');
        expect(text('[data-testid="rule-kpi"]')).toBe('Zero critical');
        choose('#rule-kind', 'Findings within thresholds');
        await settle();
        // Seven days proposed, and nothing else: no scope, no threshold.
        expect((dom().querySelector('#rule-max-age') as HTMLInputElement).value).toBe('7');
        expect(text('[data-testid="rule-described"]')).toContain('not complete yet');

        check('#rule-scope-vulnerability');
        type('#rule-max-open-critical', '0');
        type('#rule-max-age', '3');
        await settle();
        expect(text('[data-testid="rule-described"]')).toContain('Critical — at most 0 open');
        expect(text('[data-testid="rule-described"]')).toContain('Evidence at most 3 days old');
        // The organisation's plugins and SARIF tools are suggested, keyed as the server keys them.
        const suggested = Array.from(dom().querySelectorAll('#rule-scope-suggestions option')).map((option) =>
            option.getAttribute('value')
        );
        expect(suggested).toEqual([
            'import:payments-ci/semgrep oss',
            'import:payments-ci/sonarqube',
            'plugin:acme-lint'
        ]);

        button('rule-keep').click();
        fixture.detectChanges();
        expect(has('[data-testid="rule-editor"]')).toBe(false);
        expect(text('[data-testid="item-7"] [data-testid="item-rule-pending"]')).toBe('Not saved');
        expect(text('[data-testid="item-7"] [data-testid="item-rule-kind"]')).toBe('Findings within thresholds');
        expect(button('save-rules').textContent).toContain('Save the rules (1)');

        button('save-rules').click();
        const request = rulesPut();
        expect(request.request.params.get('revision')).toBe('4');
        expect(asSchema('ChecklistRulesRequest', request.request.body)).toEqual({
            items: [
                {
                    itemKey: ROW_7,
                    rule: {
                        kind: 'findings_threshold',
                        maxAgeDays: 3,
                        scopes: ['builtin:vulnerability'],
                        thresholds: { critical: { maxOpen: 0 } }
                    }
                }
            ]
        });
        request.flush(BOUND_VERSION);
        fixture.detectChanges();
        expect(text('[data-testid="notice"]')).toBe('Rules saved on 1 line(s).');
        // The version answered is adopted: its revision is the one the next write names.
        expect(text('[data-testid="shown-revision"]')).toBe('5');
        answerRereads(BOUND_VERSION);
        expect(has('[data-testid="item-rule-pending"]')).toBe(false);
        expect(text('[data-testid="item-7"] [data-testid="item-rule"]')).toContain('Exposed secret');
    });

    it('offers the secrets-at-zero preset: the secret step, critical and high at zero, seven days', async () => {
        await start('ADMIN');
        await edit(7);

        button('rule-preset-secrets').click();
        fixture.detectChanges();
        await settle();
        expect((dom().querySelector('#rule-kind') as HTMLSelectElement).selectedOptions[0].textContent?.trim()).toBe(
            'Findings within thresholds'
        );
        expect((dom().querySelector('#rule-scope-secret') as HTMLInputElement).checked).toBe(true);
        expect((dom().querySelector('#rule-max-open-critical') as HTMLInputElement).value).toBe('0');
        expect((dom().querySelector('#rule-max-open-high') as HTMLInputElement).value).toBe('0');
        expect((dom().querySelector('#rule-max-open-medium') as HTMLInputElement).value).toBe('');
        expect((dom().querySelector('#rule-max-age') as HTMLInputElement).value).toBe('7');

        const request = keepAndSave();
        expect(request.request.body).toEqual({ items: [{ itemKey: ROW_7, rule: SECRETS_RULE }] });
        request.flush(BOUND_VERSION);
        answerRereads(BOUND_VERSION);
    });

    it('binds a dependency rule, the schedule stated and the thresholds optional', async () => {
        await start('CISO');
        await edit(5);
        choose('#rule-kind', 'Dependencies analysed');
        await settle();
        expect(has('[data-testid="rule-thresholds"]')).toBe(true);

        button('rule-keep').click();
        fixture.detectChanges();
        expect(text('[data-testid="rule-error"]')).toBe(
            "Say whether the repository's schedule must run at least as often as the maximum age."
        );
        check('#rule-schedule-yes');
        type('#rule-min-resolved-high', '0.5');
        const request = keepAndSave();
        expect(request.request.body).toEqual({
            items: [
                {
                    itemKey: ROW_5,
                    rule: {
                        kind: 'dependency_analysis',
                        maxAgeDays: 7,
                        requireSchedule: true,
                        thresholds: { high: { minResolvedRatio: 0.5 } }
                    }
                }
            ]
        });
        request.flush(BOUND_VERSION);
        answerRereads(BOUND_VERSION);
    });

    it('binds a coverage rule once its metric, its minimum and its aggregation are stated', async () => {
        await start('CISO');
        await edit(5);
        choose('#rule-kind', 'Test coverage');
        await settle();

        button('rule-keep').click();
        fixture.detectChanges();
        expect(text('[data-testid="rule-error"]')).toBe('Choose what the coverage counts: lines or branches.');
        choose('#rule-metric', 'branches');
        type('#rule-minimum-ratio', '0');
        button('rule-keep').click();
        fixture.detectChanges();
        expect(text('[data-testid="rule-error"]')).toContain('above 0 and up to 1');
        type('#rule-minimum-ratio', '0.75');
        choose('#rule-aggregation', 'over the project, weighted by size');
        await settle();
        expect(text('[data-testid="rule-described"]')).toContain(
            'Coverage of branches at least 75 %, over the project, weighted by size'
        );
        const request = keepAndSave();
        expect(request.request.body).toEqual({
            items: [
                {
                    itemKey: ROW_5,
                    rule: {
                        kind: 'coverage_threshold',
                        maxAgeDays: 7,
                        metric: 'branch',
                        minimumRatio: 0.75,
                        aggregation: 'project_weighted'
                    }
                }
            ]
        });
        request.flush(BOUND_VERSION);
        answerRereads(BOUND_VERSION);
    });

    it('binds a test-suite rule: a pattern and at least one test', async () => {
        await start('CISO');
        await edit(5);
        choose('#rule-kind', 'Test suite passed');
        await settle();

        type('#rule-pattern', ' com.example.arch.* ');
        type('#rule-minimum-tests', '0');
        button('rule-keep').click();
        fixture.detectChanges();
        expect(text('[data-testid="rule-error"]')).toBe(
            'State the least number of tests the suites must run: a whole number, 1 to 10000000.'
        );
        type('#rule-minimum-tests', '12');
        const request = keepAndSave();
        expect(request.request.body).toEqual({
            items: [
                {
                    itemKey: ROW_5,
                    rule: {
                        kind: 'test_suite_passed',
                        maxAgeDays: 7,
                        suitePattern: 'com.example.arch.*',
                        minimumTests: 12
                    }
                }
            ]
        });
        request.flush(BOUND_VERSION);
        answerRereads(BOUND_VERSION);
    });

    it('binds a component rule: each package by its versionless URL, its versions an explicit list', async () => {
        await start('CISO');
        await edit(5);
        choose('#rule-kind', 'Component versions allowed');
        await settle();

        button('rule-keep').click();
        fixture.detectChanges();
        expect(text('[data-testid="rule-error"]')).toBe('Declare 1 to 50 packages.');
        button('rule-component-add').click();
        fixture.detectChanges();
        type('#rule-purl-0', 'pkg:maven/com.example/ledger-core@3.2');
        type('#rule-versions-0', '3.2.1, 3.3.0');
        button('rule-keep').click();
        fixture.detectChanges();
        expect(text('[data-testid="rule-error"]')).toContain('is no package URL without its version');
        type('#rule-purl-0', 'pkg:maven/com.example/ledger-core');
        const request = keepAndSave();
        expect(request.request.body).toEqual({
            items: [
                {
                    itemKey: ROW_5,
                    rule: {
                        kind: 'component_versions',
                        maxAgeDays: 7,
                        components: [{ purlPrefix: 'pkg:maven/com.example/ledger-core', versions: ['3.2.1', '3.3.0'] }]
                    }
                }
            ]
        });
        request.flush(BOUND_VERSION);
        answerRereads(BOUND_VERSION);
    });

    it('refuses a maximum age past a year and a day, and a malformed scope, before sending anything', async () => {
        await start('CISO');
        await edit(7);
        button('rule-preset-secrets').click();
        fixture.detectChanges();
        type('#rule-max-age', '367');
        button('rule-keep').click();
        fixture.detectChanges();
        expect(text('[data-testid="rule-error"]')).toBe(
            'State the maximum age of the evidence: a whole number of days, 1 to 366.'
        );

        type('#rule-max-age', '366');
        type('#rule-scope-other', 'plugin:Not_An_Id');
        button('rule-scope-add').click();
        fixture.detectChanges();
        button('rule-keep').click();
        fixture.detectChanges();
        expect(text('[data-testid="rule-error"]')).toBe(
            '"plugin:Not_An_Id" is no scope: builtin:<step>, plugin:<id> or import:<source>/<tool>.'
        );
        button('Remove the scope plugin:Not_An_Id').click();
        fixture.detectChanges();
        expect(has('[data-testid="rule-editor"]')).toBe(true);
        http.expectNone((call) => call.method === 'PUT');
    });

    it('sends nothing for a rule reopened and kept as it was, and unbinds a line with a null rule', async () => {
        await start('CISO', { ...CONFIRMED_PREVIEW, version: { ...DRAFT, revision: 5 } }, BOUND_VERSION);

        expect(text('[data-testid="item-5"] [data-testid="item-rule-kind"]')).toBe('Test coverage');
        expect(text('[data-testid="item-5"] [data-testid="item-rule"]')).toContain(
            'Coverage of lines at least 80 %, on every repository'
        );
        await edit(5);
        expect((dom().querySelector('#rule-minimum-ratio') as HTMLInputElement).value).toBe('0.8');
        button('rule-keep').click();
        fixture.detectChanges();
        expect(has('[data-testid="item-rule-pending"]')).toBe(false);
        expect(button('save-rules').disabled).toBe(true);

        await edit(7, false);
        choose('#rule-kind', 'No rule');
        await settle();
        expect(text('[data-testid="rule-described"]')).toContain('nothing is measured beside it');
        button('rule-unbind').click();
        fixture.detectChanges();
        expect(text('[data-testid="item-7"] [data-testid="item-rule"]')).toContain('No rule');
        button('save-rules').click();
        const request = rulesPut();
        expect(request.request.params.get('revision')).toBe('5');
        expect(asSchema('ChecklistRulesRequest', request.request.body)).toEqual({
            items: [{ itemKey: ROW_7, rule: null }]
        });
        request.flush(VERSION);
        answerRereads(VERSION);
    });

    it('undoes a rule kept on screen, which is then not sent', async () => {
        await start('CISO');
        await edit(7);
        button('rule-preset-secrets').click();
        fixture.detectChanges();
        button('rule-keep').click();
        fixture.detectChanges();
        expect(button('save-rules').disabled).toBe(false);

        button('Undo the rule change on row 7').click();
        fixture.detectChanges();
        expect(button('save-rules').disabled).toBe(true);
        expect(text('[data-testid="item-7"] [data-testid="item-rule"]')).toContain('No rule');
    });

    it("explains a binding refused for a draft changed meanwhile, and shows another refusal in the server's words", async () => {
        await start('CISO');
        await edit(7);
        button('rule-preset-secrets').click();
        fixture.detectChanges();
        keepAndSave().flush(conflict('checklist-template-changed'), { status: 409, statusText: 'Conflict' });
        fixture.detectChanges();
        expect(text('[data-testid="refusal-message"]')).toContain('you had revision 4 on screen');
        expect(has('[data-testid="rules-error"]')).toBe(false);

        button('save-rules').click();
        rulesPut().flush(
            { type: 'about:blank', title: 'Bad Request', status: 400, detail: 'No built-in step examines ai_review.' },
            { status: 400, statusText: 'Bad Request' }
        );
        fixture.detectChanges();
        expect(text('[data-testid="rules-error"]')).toBe('No built-in step examines ai_review.');
    });

    it('shows an auditor what each line is measured by, in words, and nothing to change', async () => {
        await start('AUDITOR', { ...CONFIRMED_PREVIEW, version: { ...DRAFT, revision: 5 } }, BOUND_VERSION);

        expect(text('[data-testid="item-7"] [data-testid="item-rule"]')).toContain('Critical — at most 0 open');
        expect(text('[data-testid="rules-explain"]')).toContain('by a security lead');
        expect(has('[id^="edit-rule-"]')).toBe(false);
        expect(has('#save-rules')).toBe(false);
    });

    it('offers no binding on a published version, even to a security lead: it never changes', async () => {
        await start('CISO', { ...CONFIRMED_PREVIEW, version: PUBLISHED }, { ...BOUND_VERSION, version: PUBLISHED });

        expect(text('[data-testid="item-7"] [data-testid="item-rule-kind"]')).toBe('Findings within thresholds');
        expect(text('[data-testid="rules-explain"]')).toContain('derive a new one');
        expect(has('[id^="edit-rule-"]')).toBe(false);
        expect(has('#save-rules')).toBe(false);
    });

    it('offers no binding on a draft whose layout is not confirmed: it has no line yet', async () => {
        await start('CISO', PREVIEW);

        expect(has('[id^="edit-rule-"]')).toBe(false);
        expect(has('#save-rules')).toBe(false);
    });
});

describe('the rule changes a template sends', () => {
    it('lists the lines whose rule moved, in the version order, and none edited back to what it was', () => {
        expect(ruleChangesOf(BOUND_VERSION.items, {})).toEqual([]);
        expect(
            ruleChangesOf(BOUND_VERSION.items, {
                'text:dependencies carry no known critical vulnerability': SECRETS_RULE,
                'text:secrets are rotated every ninety days': SECRETS_RULE,
                'text:service accounts hold no interactive login': null
            })
        ).toEqual([
            { itemKey: 'text:service accounts hold no interactive login', rule: null },
            { itemKey: 'text:secrets are rotated every ninety days', rule: SECRETS_RULE }
        ]);
    });
});
