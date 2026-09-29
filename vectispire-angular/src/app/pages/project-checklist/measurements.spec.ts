import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting, TestRequest } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { afterEach, describe, expect, it } from 'vitest';
import type {
    ChecklistLine,
    ChecklistMeasurements,
    ChecklistView,
    MeasuredLine,
    NoDataReason
} from '@/app/core/api.models';
import { SessionStore } from '@/app/core/session.store';
import {
    CARRIED_LINE,
    conflict,
    COVERAGE_RULE,
    CONTEXT,
    FAIL_MEASUREMENT,
    MEASURED_CHECKLIST,
    MEASURED_OPEN_LINE,
    MEASURED_READY_LINE,
    measuredLine,
    measurement,
    MEASUREMENTS,
    NO_DATA_MEASUREMENT,
    PASS_MEASUREMENT,
    PROJECT_ID,
    READY_CHECKLIST,
    SIGNED_CHECKLIST,
    SIGNED_REVISION,
    SUBMITTED_CHECKLIST
} from '@/app/core/testing/checklists.fixtures';
import { asSchema } from '@/app/core/testing/contract';
import { useEnglish } from '@/app/core/testing/english';
import english from '../../../../public/i18n/en.json';
import french from '../../../../public/i18n/fr.json';
import {
    changedSinceSubmission,
    LOOK_STATUS_KEYS,
    MEASURED_PROBLEM_KEYS,
    measuredAnswer,
    measuredConflictLinesOf,
    NO_DATA_KEYS,
    NO_DATA_SHORT_KEYS,
    OUTCOME_KEYS,
    RECONCILIATION_KEYS,
    SOURCE_KEYS
} from './measurements';
import { AS_MEASURED_SKIP_KEYS, ProjectChecklist } from './project-checklist';

/**
 * A project checklist's measured lines (decision 0032 §6), through the DOM.
 *
 * What it must get right: every bound line shows what its rule found — met, not met, or no data and
 * why, in the reader's words for every reason the server names — with its evidence on demand; the one
 * click sends the person's answer resting on the measurement they read, and a measurement that moved
 * in between is read again and said so; the submission is offered on the view's `readyToSubmit` alone,
 * which on a draft already counts what the measurement would refuse, and a measured obstacle is said
 * once — by the line's problems, not again by the measurement's badge; and the two measurement refusals
 * point at the lines they name.
 */
describe('the measured lines of a project checklist', () => {
    let fixture: ComponentFixture<ProjectChecklist>;
    let http: HttpTestingController;

    const BASE = `/api/v1/projects/${PROJECT_ID}/checklists`;

    afterEach(() => {
        try {
            http?.verify();
        } finally {
            TestBed.resetTestingModule();
        }
    });

    async function start(
        role: string,
        view: ChecklistView = MEASURED_CHECKLIST,
        measured: ChecklistMeasurements | null = MEASUREMENTS,
        username = 'erin'
    ): Promise<void> {
        await TestBed.configureTestingModule({
            imports: [ProjectChecklist],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();
        TestBed.inject(SessionStore).open('token', {
            username,
            displayName: null,
            role,
            mustChangePassword: false,
            mfaEnabled: false
        });
        useEnglish();
        fixture = TestBed.createComponent(ProjectChecklist);
        fixture.componentRef.setInput('projectId', String(PROJECT_ID));
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        const revisions = [view.checklist, SIGNED_REVISION];
        http.expectOne({ method: 'GET', url: `${BASE}/context` }).flush({
            ...CONTEXT,
            latestRevision: view.checklist.revision,
            latestEdition: view.checklist.edition
        });
        http.expectOne({ method: 'GET', url: BASE }).flush(revisions);
        for (const offered of http.match({ method: 'GET', url: `${BASE}/offered` })) offered.flush([]);
        http.expectOne({ method: 'GET', url: `${BASE}/${view.checklist.revision}` }).flush(view);
        fixture.detectChanges();
        if (measured) {
            measurementsRead(view.checklist.revision).flush(measured);
            fixture.detectChanges();
        }
    }

    const measurementsRead = (revision = 2): TestRequest =>
        http.expectOne({ method: 'GET', url: `${BASE}/${revision}/measurements` });

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

    function click(idOrName: string): void {
        button(idOrName).click();
        fixture.detectChanges();
    }

    function type(selector: string, value: string): void {
        const input = dom().querySelector(selector) as HTMLInputElement | HTMLTextAreaElement;
        input.value = value;
        input.dispatchEvent(new Event('input'));
        fixture.detectChanges();
    }

    /** The live measurements with line 3's replaced. */
    const withLine3 = (line: MeasuredLine): ChecklistMeasurements => ({
        ...MEASUREMENTS,
        lines: [MEASUREMENTS.lines[0], line]
    });

    const refuse = (request: TestRequest, token: string, lines: unknown[]) => {
        request.flush(conflict(token, undefined, { lines }), { status: 409, statusText: 'Conflict' });
        fixture.detectChanges();
    };

    // ------------------------------------------------------------------ what each line shows

    it('shows each bound line beside its answer — met, or no data and why — and says the measurements are live', async () => {
        await start('USER');

        expect(text('[data-testid="measurements-mode"]')).toContain('Measurements computed now (28/09/2026');
        expect(text('[data-testid="measurements-mode"]')).toContain('computed again at the submission');

        const coverage = '[data-testid="measurement-1"]';
        expect(text(`${coverage} [data-testid="rule-kind"]`)).toBe('Test coverage');
        expect(text(`${coverage} [data-testid="rule-words"]`)).toContain('Coverage of lines at least 80 %');
        expect(text(`${coverage} [data-testid="outcome"]`)).toBe('Met');
        expect(text(`${coverage} [data-testid="reconciliation"]`)).toBe('Consistent');
        expect(text(`${coverage} [data-testid="as-of"]`)).toContain('As of 27/09/2026');
        expect(has(`${coverage} [data-testid="reason"]`)).toBe(false);

        const secrets = '[data-testid="measurement-3"]';
        expect(text(`${secrets} [data-testid="outcome"]`)).toBe('No data');
        expect(text(`${secrets} [data-testid="reason"]`)).toBe(
            'A repository has never been examined for this: no scan or import in which the step looked. Not "nothing found" — nothing looked.'
        );
        expect(text(`${secrets} [data-testid="reconciliation"]`)).toBe('Not answered yet');
        expect(text(`${secrets} [data-testid="as-of"]`)).toBe('It rests on no evidence.');
        expect(text(`${secrets} [data-testid="figures"]`)).toContain('All scopes');
        expect(text(`${secrets} [data-testid="figures"]`)).toContain('Critical');

        // A line bound to no rule shows no measurement at all.
        expect(has('[data-testid="measurement-2"]')).toBe(false);
    });

    it.each(Object.keys(NO_DATA_KEYS) as NoDataReason[])(
        'says why there is no data in words for %s, never as a raw token',
        async (reason) => {
            await start(
                'USER',
                MEASURED_CHECKLIST,
                withLine3(measuredLine(MEASURED_OPEN_LINE, measurement(103, { reason })))
            );
            const sentence = (english.project_checklist as Record<string, string>)[NO_DATA_KEYS[reason].split('.')[1]];
            expect(sentence.length).toBeGreaterThan(20);
            expect(text('[data-testid="measurement-3"] [data-testid="reason"]')).toBe(sentence);
            expect(text('[data-testid="measurement-3"]')).not.toContain(reason);
        }
    );

    it('shows the evidence per repository on demand: what was read, when, its digest, whether it met', async () => {
        await start('USER');

        expect(has('[data-testid="measured-evidence-1"]')).toBe(false);
        click('Evidence measured for line 1');
        const coverage = text('[data-testid="measured-evidence-1"]');
        // By its name, as every screen names a repository — not by its id.
        expect(coverage).toContain('checkout-api');
        expect(coverage).not.toContain('#31');
        expect(coverage).toContain('examined');
        expect(coverage).toContain('Coverage report 77');
        expect(coverage).toContain('27/09/2026');
        expect(coverage).toContain('ffffffffffff');
        expect(coverage).toContain('line coverage 0.86, at least 0.8');

        click('Evidence measured for line 3');
        const secrets = text('[data-testid="measured-evidence-3"]');
        expect(secrets).toContain('Exposed secret');
        expect(secrets).toContain('never examined');
        click('Evidence measured for line 3');
        expect(has('[data-testid="measured-evidence-3"]')).toBe(false);
    });

    it('names a repository no longer in the project by its id, since it has no name to show', async () => {
        const gone = {
            ...PASS_MEASUREMENT,
            evidence: {
                ...PASS_MEASUREMENT.evidence,
                repositories: [{ ...PASS_MEASUREMENT.evidence.repositories[0], repositoryName: null }]
            }
        };
        await start('USER', MEASURED_CHECKLIST, {
            ...MEASUREMENTS,
            lines: [measuredLine(MEASURED_READY_LINE, gone), MEASUREMENTS.lines[1]]
        });

        click('Evidence measured for line 1');
        const cell = dom().querySelector('[data-testid="measured-evidence-1"] tbody td');
        expect(cell?.textContent?.trim()).toBe('#31');
        expect(text('[data-testid="measured-evidence-1"]')).not.toContain('null');
    });

    it('links a scan the measurement read to its page, and marks the threshold not met', async () => {
        await start('USER', MEASURED_CHECKLIST, withLine3(measuredLine(MEASURED_OPEN_LINE, FAIL_MEASUREMENT)));

        expect(text('[data-testid="measurement-3"] [data-testid="outcome"]')).toBe('Not met');
        expect(text('[data-testid="measurement-3"] [data-testid="figures"]')).toContain(
            'Not met · 2 open, more than 0'
        );
        click('Evidence measured for line 3');
        const link = dom().querySelector('[data-testid="measured-evidence-3"] a') as HTMLAnchorElement;
        expect(link.textContent?.trim()).toBe('Scan 501');
        expect(link.getAttribute('href')).toBe('/scans/501');
    });

    it('reads no measurement for a checklist measured by no rule', async () => {
        await start('USER', { ...MEASURED_CHECKLIST, lines: [CARRIED_LINE] }, null);

        http.expectNone((call) => call.url.endsWith('/measurements'));
        expect(has('[data-testid="measurements-mode"]')).toBe(false);
    });

    it('says a measurement could not be read, and neither waits for it nor holds the submission back for it', async () => {
        await start('USER', { ...READY_CHECKLIST, lines: [MEASURED_READY_LINE] }, null);

        // The view's readiness already counts the measurement: the submission does not wait for the route.
        expect(button('submit-checklist').disabled).toBe(false);
        measurementsRead().flush({ detail: 'down' }, { status: 503, statusText: 'Unavailable' });
        fixture.detectChanges();
        expect(text('[data-testid="measurements-error"]')).toBe('down');
        expect(button('submit-checklist').disabled).toBe(false);
    });

    // ------------------------------------------------------------------ the one click

    it('answers yes as measured in one click, resting on the evidence digest read, then reads the measurements again', async () => {
        await start('USER');

        click('Answer line 1 as measured');
        const request = http.expectOne({ method: 'POST', url: `${BASE}/2/items/101/answers` });
        expect(asSchema('ChecklistAnswerRequest', request.request.body)).toEqual({
            value: 'yes',
            edition: 5,
            measurementDigest: PASS_MEASUREMENT.evidenceDigest
        });
        request.flush(MEASURED_CHECKLIST, { status: 201, statusText: 'Created' });
        fixture.detectChanges();
        measurementsRead().flush(MEASUREMENTS);
    });

    it('opens a no as measured with the measurement kept, sent only while no is the answer chosen', async () => {
        await start('USER', MEASURED_CHECKLIST, withLine3(measuredLine(MEASURED_OPEN_LINE, FAIL_MEASUREMENT)));

        expect(button('Answer line 3 as measured').textContent).toContain('Answer no, as measured');
        click('Answer line 3 as measured');
        http.expectNone((call) => call.method === 'POST');
        expect((dom().querySelector('#answer-103-no') as HTMLInputElement).checked).toBe(true);
        expect(text('[data-testid="answer-resting"]')).toContain('rests on the measurement read at 28/09/2026');

        // A no needs its comment, measured or not.
        click('save-answer-103');
        expect(text('[data-testid="answer-error"]')).not.toBe('');
        type('#comment-103', 'Two leaked tokens, rotation planned.');
        click('save-answer-103');
        const resting = http.expectOne({ method: 'POST', url: `${BASE}/2/items/103/answers` });
        expect(resting.request.body).toEqual({
            value: 'no',
            comment: 'Two leaked tokens, rotation planned.',
            edition: 5,
            measurementDigest: FAIL_MEASUREMENT.evidenceDigest
        });
        resting.flush(MEASURED_CHECKLIST, { status: 201, statusText: 'Created' });
        fixture.detectChanges();
        measurementsRead().flush(MEASUREMENTS);
    });

    it('drops the measurement from an answer other than the measured one', async () => {
        await start('USER', MEASURED_CHECKLIST, withLine3(measuredLine(MEASURED_OPEN_LINE, FAIL_MEASUREMENT)));

        click('Answer line 3 as measured');
        const yes = dom().querySelector('#answer-103-yes') as HTMLInputElement;
        yes.checked = true;
        yes.dispatchEvent(new Event('change'));
        fixture.detectChanges();
        expect(text('[data-testid="answer-resting"]')).toBe(
            'Another answer than the measured one rests on no measurement.'
        );
        click('save-answer-103');
        const plain = http.expectOne({ method: 'POST', url: `${BASE}/2/items/103/answers` });
        expect(plain.request.body).toEqual({ value: 'yes', edition: 5 });
        plain.flush(MEASURED_CHECKLIST, { status: 201, statusText: 'Created' });
        fixture.detectChanges();
        measurementsRead().flush(MEASUREMENTS);
    });

    it('offers no one click where there is no data: the person answers, and a yes then needs a comment and a proof', async () => {
        await start('USER');

        expect(has('#answer-measured-103')).toBe(false);
        expect(text('[data-testid="measurement-3"] [data-testid="no-one-click"]')).toContain(
            'A yes where there is no data needs a comment and a proof.'
        );
    });

    it('reads the measurement again when it moved since it was read, and says so on the line', async () => {
        await start('USER');

        click('Answer line 1 as measured');
        refuse(
            http.expectOne({ method: 'POST', url: `${BASE}/2/items/101/answers` }),
            'checklist-measurement-changed',
            [
                {
                    itemId: 101,
                    position: 1,
                    answer: 'yes',
                    outcome: 'no_data',
                    reason: 'stale',
                    submittedOutcome: null,
                    submittedReason: null
                }
            ]
        );
        expect(text('[data-testid="line-1"] [data-testid="refusal-message"]')).toBe(
            'The measurement changed since you read it: it is read again here. Check what it says now, then answer.'
        );
        expect(text('[data-testid="measured-conflict-1"]')).toContain('Answered Yes, measured No data (too old)');
        const stale = measurement(101, {
            ruleKind: 'coverage_threshold',
            reason: 'stale',
            evidenceDigest: '4'.repeat(64)
        });
        measurementsRead().flush({
            ...MEASUREMENTS,
            lines: [measuredLine(MEASURED_READY_LINE, stale), MEASUREMENTS.lines[1]]
        });
        fixture.detectChanges();
        expect(text('[data-testid="measurement-1"] [data-testid="reason"]')).toBe(
            'The newest evidence is older than the rule’s maximum age.'
        );
    });

    it('offers an auditor the measurements and no answer to give', async () => {
        await start('AUDITOR');

        expect(text('[data-testid="measurement-1"] [data-testid="outcome"]')).toBe('Met');
        expect(has('[id^="answer-measured-"]')).toBe(false);
        expect(has('[data-testid="no-one-click"]')).toBe(false);
    });

    // ------------------------------------------------------------------ every measured line, in one act

    /** Line 1 unanswered and met, line 2 answered and met, line 3 unanswered and not met. */
    const UNANSWERED_MET: ChecklistLine = { ...MEASURED_READY_LINE, answer: null, problems: ['unanswered'] };
    const ANSWERED_MET: ChecklistLine = { ...CARRIED_LINE, rule: COVERAGE_RULE };
    const OFFERING: ChecklistView = asSchema('ChecklistView', {
        ...MEASURED_CHECKLIST,
        lines: [UNANSWERED_MET, ANSWERED_MET, MEASURED_OPEN_LINE]
    });
    const MET_UNANSWERED = measurement(101, {
        ...PASS_MEASUREMENT,
        answerId: null,
        answerValue: null,
        reconciliation: 'unanswered'
    });
    const MET_ANSWERED = measurement(102, { ...PASS_MEASUREMENT, itemId: 102, evidenceDigest: '5'.repeat(64) });
    const OFFERED_MEASUREMENTS: ChecklistMeasurements = {
        ...MEASUREMENTS,
        lines: [
            measuredLine(UNANSWERED_MET, MET_UNANSWERED),
            measuredLine(ANSWERED_MET, MET_ANSWERED),
            measuredLine(MEASURED_OPEN_LINE, FAIL_MEASUREMENT)
        ]
    };
    /** The view once line 1 is answered yes. */
    const AFTER: ChecklistView = asSchema('ChecklistView', {
        ...OFFERING,
        checklist: { ...OFFERING.checklist, edition: 6 },
        lines: [MEASURED_READY_LINE, ANSWERED_MET, MEASURED_OPEN_LINE]
    });
    const skip = (itemId: number, position: number, reason: string, extra: Record<string, unknown> = {}) => ({
        itemId,
        position,
        reason,
        outcome: 'pass',
        noDataReason: null,
        evidenceDigest: 'a'.repeat(64),
        answer: null,
        ...extra
    });
    const actUrl = `${BASE}/2/answers/as-measured`;

    it('sends every unanswered line its button offers, each with the digest shown, and no other', async () => {
        await start('USER', OFFERING, OFFERED_MEASUREMENTS);

        expect(button('answer-all-measured').textContent).toContain('Answer every measured line as measured');
        click('answer-all-measured');
        const act = http.expectOne({ method: 'POST', url: actUrl });
        expect(asSchema('ChecklistAsMeasuredRequest', act.request.body)).toEqual({
            edition: 5,
            lines: [
                { itemId: 101, measurementDigest: MET_UNANSWERED.evidenceDigest },
                { itemId: 103, measurementDigest: FAIL_MEASUREMENT.evidenceDigest }
            ]
        });
        act.flush(
            asSchema('ChecklistAsMeasuredView', {
                checklist: AFTER,
                answered: [
                    {
                        itemId: 101,
                        position: 1,
                        value: 'yes',
                        answerId: 700,
                        measurementId: 800,
                        evidenceDigest: MET_UNANSWERED.evidenceDigest
                    }
                ],
                skipped: [
                    skip(102, 2, 'already_answered', { answer: 'yes' }),
                    skip(103, 3, 'needs_comment', { outcome: 'fail' })
                ]
            })
        );
        fixture.detectChanges();
        measurementsRead().flush({
            ...OFFERED_MEASUREMENTS,
            lines: [
                measuredLine(MEASURED_READY_LINE, PASS_MEASUREMENT),
                OFFERED_MEASUREMENTS.lines[1],
                OFFERED_MEASUREMENTS.lines[2]
            ]
        });
        fixture.detectChanges();

        expect(text('[data-testid="line-1"] [data-testid="answer-value"]')).toBe('Yes');
        expect(text('[data-testid="as-measured-answered"]')).toBe('1 line(s) answered yes as measured.');
        expect(text('[data-testid="as-measured-needs_comment"]')).toContain(
            'Lines 3, measured as not met, need your “no” with a comment:'
        );
        // Line 2 was answered before the act and not sent: naming it would bury what the act did.
        expect(has('[data-testid="as-measured-already_answered"]')).toBe(false);
        // Line 3 alone still offers the one click, and the act is offered for it: its no is still owed.
        expect(has('#answer-all-measured')).toBe(true);
    });

    it('offers the act on no line answered, no line without data, and no revision the person cannot answer', async () => {
        // Line 1 answered, line 3 without data: no button offers the one click on an unanswered line.
        await start('USER');
        expect(has('#answer-measured-101')).toBe(true);
        expect(has('#answer-all-measured')).toBe(false);
        TestBed.resetTestingModule();

        await start('AUDITOR', OFFERING, OFFERED_MEASUREMENTS);
        expect(has('#answer-all-measured')).toBe(false);
        TestBed.resetTestingModule();

        const submitted = asSchema('ChecklistView', { ...OFFERING, checklist: SUBMITTED_CHECKLIST.checklist });
        await start('USER', submitted, {
            ...OFFERED_MEASUREMENTS,
            revision: submitted.checklist.revision,
            status: 'submitted'
        });
        expect(has('#answer-all-measured')).toBe(false);
        TestBed.resetTestingModule();

        // Frozen measurements are read, not answered.
        await start('USER', OFFERING, { ...OFFERED_MEASUREMENTS, live: false });
        expect(has('#answer-all-measured')).toBe(false);
    });

    it('names what it left alone by reason, in plain words, and a line answered meanwhile only if it was sent', async () => {
        await start('USER', OFFERING, OFFERED_MEASUREMENTS);

        click('answer-all-measured');
        http.expectOne({ method: 'POST', url: actUrl }).flush(
            asSchema('ChecklistAsMeasuredView', {
                checklist: OFFERING,
                answered: [],
                skipped: [
                    skip(103, 3, 'measurement_changed', { outcome: 'no_data', noDataReason: 'stale' }),
                    skip(105, 5, 'no_data', { outcome: 'no_data', noDataReason: 'never_examined' }),
                    skip(104, 4, 'no_data', { outcome: 'no_data', noDataReason: 'step_absent' }),
                    skip(106, 6, 'not_shown'),
                    skip(101, 1, 'already_answered', { answer: 'no' })
                ]
            })
        );
        fixture.detectChanges();
        measurementsRead().flush(OFFERED_MEASUREMENTS);
        fixture.detectChanges();

        expect(text('[data-testid="as-measured-answered"]')).toBe('0 line(s) answered yes as measured.');
        expect(text('[data-testid="as-measured-measurement_changed"]')).toBe(
            'The measurement of lines 3 changed since you read it: check it again, then answer.'
        );
        expect(text('[data-testid="as-measured-no_data"]')).toBe(
            'Lines 4, 5 have no data: answer them yourself — a yes there needs a comment and a proof.'
        );
        expect(text('[data-testid="as-measured-not_shown"]')).toContain('Lines 6 are measured met now');
        expect(text('[data-testid="as-measured-already_answered"]')).toBe(
            'Lines 1 were answered meanwhile: their answer is left as it is.'
        );
        expect(has('[data-testid="as-measured-needs_comment"]')).toBe(false);

        click('dismiss-as-measured');
        expect(has('[data-testid="as-measured-summary"]')).toBe(false);
    });

    it('opens a line left for its no on no, resting on the measurement, and drops it once answered', async () => {
        await start('USER', OFFERING, OFFERED_MEASUREMENTS);

        click('answer-all-measured');
        http.expectOne({ method: 'POST', url: actUrl }).flush(
            asSchema('ChecklistAsMeasuredView', {
                checklist: AFTER,
                answered: [],
                skipped: [
                    skip(103, 3, 'needs_comment', { outcome: 'fail', evidenceDigest: FAIL_MEASUREMENT.evidenceDigest })
                ]
            })
        );
        fixture.detectChanges();
        measurementsRead().flush(OFFERED_MEASUREMENTS);
        fixture.detectChanges();

        expect(button('as-measured-no-103').textContent).toContain('Line 3: answer no');
        click('as-measured-no-103');
        await fixture.whenStable();
        http.expectNone((call) => call.method === 'POST');
        expect((dom().querySelector('#answer-103-no') as HTMLInputElement).checked).toBe(true);
        expect(text('[data-testid="answer-resting"]')).toContain('rests on the measurement read at');
        expect(document.activeElement?.id).toBe('comment-103');

        type('#comment-103', 'Two leaked tokens, rotation planned.');
        click('save-answer-103');
        const no = http.expectOne({ method: 'POST', url: `${BASE}/2/items/103/answers` });
        expect(no.request.body).toEqual({
            value: 'no',
            comment: 'Two leaked tokens, rotation planned.',
            edition: 6,
            measurementDigest: FAIL_MEASUREMENT.evidenceDigest
        });
        const answeredNo: ChecklistLine = {
            ...MEASURED_OPEN_LINE,
            answer: { ...READY_CHECKLIST.lines[0].answer!, id: 604, itemId: 103, value: 'no' },
            problems: []
        };
        no.flush(
            { ...AFTER, lines: [MEASURED_READY_LINE, ANSWERED_MET, answeredNo] },
            { status: 201, statusText: 'Created' }
        );
        fixture.detectChanges();
        measurementsRead().flush(OFFERED_MEASUREMENTS);
        fixture.detectChanges();
        expect(has('[data-testid="as-measured-needs_comment"]')).toBe(false);
        expect(has('[data-testid="as-measured-summary"]')).toBe(true);
    });

    it('explains a refusal by its problem type, offering the reload a stale checklist needs', async () => {
        await start('USER', OFFERING, OFFERED_MEASUREMENTS);

        click('answer-all-measured');
        http.expectOne({ method: 'POST', url: actUrl }).flush(conflict('checklist-changed'), {
            status: 409,
            statusText: 'Conflict'
        });
        fixture.detectChanges();
        expect(text('[data-testid="refusal-message"]')).toBe(
            'The checklist changed since you read it. Reload it, look at what changed, then try again.'
        );
        expect(has('[data-testid="as-measured-summary"]')).toBe(false);

        click('reload-checklist');
        http.expectOne({ method: 'GET', url: `${BASE}/context` }).flush({
            ...CONTEXT,
            latestRevision: 2,
            latestEdition: 6
        });
        http.expectOne({ method: 'GET', url: BASE }).flush([AFTER.checklist, SIGNED_REVISION]);
        for (const offered of http.match({ method: 'GET', url: `${BASE}/offered` })) offered.flush([]);
        http.expectOne({ method: 'GET', url: `${BASE}/2` }).flush(AFTER);
        fixture.detectChanges();
        measurementsRead().flush(OFFERED_MEASUREMENTS);
        fixture.detectChanges();
        expect(has('[data-testid="refusal"]')).toBe(false);

        click('answer-all-measured');
        http.expectOne({ method: 'POST', url: actUrl }).flush(conflict('checklist-not-draft'), {
            status: 409,
            statusText: 'Conflict'
        });
        fixture.detectChanges();
        expect(text('[data-testid="refusal-message"]')).toContain('This revision is no longer a draft');
        expect(has('#reload-checklist')).toBe(true);
    });

    // ------------------------------------------------------------------ badges and the submission

    /** Line 3 answered yes, with the view counting what the measurement makes of it, as a draft's read does. */
    const answeredYes = (problems: ChecklistLine['problems']): ChecklistLine => ({
        ...MEASURED_OPEN_LINE,
        answer: { ...READY_CHECKLIST.lines[0].answer!, id: 603, itemId: 103 },
        problems
    });
    const lineProblems = (position: number) =>
        Array.from(dom().querySelectorAll(`[data-testid="line-${position}"] [data-testid="problems"] p-tag`)).map(
            (tag) => tag.textContent?.trim()
        );
    const badges = (position: number) =>
        Array.from(
            dom().querySelectorAll(`[data-testid="measurement-${position}"] [data-testid="measured-problem"]`)
        ).map((tag) => tag.textContent?.trim());

    it('keeps back a draft whose only obstacle is a failing measurement, and says so once, on the line', async () => {
        const contradicted = answeredYes(['measurement_contradicted']);
        const view: ChecklistView = {
            ...READY_CHECKLIST,
            readyToSubmit: false,
            lines: [MEASURED_READY_LINE, READY_CHECKLIST.lines[1], contradicted]
        };
        await start(
            'USER',
            view,
            withLine3(
                measuredLine(
                    contradicted,
                    { ...FAIL_MEASUREMENT, reconciliation: 'contradicted' },
                    { reconciliation: 'contradicted', problems: ['measurement_contradicted'] }
                )
            )
        );

        expect(button('submit-checklist').disabled).toBe(true);
        expect(text('[data-testid="submit-blocked"]')).toBe('Not ready to submit: lines 3 still need attention.');
        expect(text('[data-testid="measurement-3"] [data-testid="reconciliation"]')).toBe(
            'Contradicted: yes where the measurement is not met'
        );
        const sentence = 'A yes against a measurement not met is refused at the submission';
        expect(lineProblems(3)).toEqual([sentence]);
        expect(badges(3)).toEqual([]);
        expect(text('[data-testid="line-3"]').split(sentence)).toHaveLength(2);
    });

    it('names what a yes without data still needs by the line, as the view counts it, and no badge again', async () => {
        const answered = answeredYes(['comment_required', 'evidence_required']);
        const view: ChecklistView = {
            ...READY_CHECKLIST,
            readyToSubmit: false,
            lines: [MEASURED_READY_LINE, READY_CHECKLIST.lines[1], answered]
        };
        const declared = measuredLine(
            answered,
            { ...NO_DATA_MEASUREMENT, reconciliation: 'declared_not_measured' },
            { reconciliation: 'declared_not_measured', problems: ['comment_required', 'evidence_required'] }
        );
        await start('USER', view, withLine3(declared));

        expect(text('[data-testid="measurement-3"] [data-testid="reconciliation"]')).toBe('Declared, not measured');
        expect(lineProblems(3)).toEqual(['Comment required', 'Evidence required']);
        expect(badges(3)).toEqual([]);
        expect(button('submit-checklist').disabled).toBe(true);
        expect(text('[data-testid="submit-blocked"]')).toBe('Not ready to submit: lines 3 still need attention.');
    });

    it('still badges what the measurement says and the line does not', async () => {
        await start(
            'USER',
            MEASURED_CHECKLIST,
            withLine3(measuredLine(MEASURED_OPEN_LINE, NO_DATA_MEASUREMENT, { problems: ['evidence_expired'] }))
        );

        expect(badges(3)).toEqual(['No data: the proof of this yes is out of date']);
    });

    it('offers the submission the view says is ready, whatever the measurements route answers', async () => {
        await start(
            'USER',
            { ...READY_CHECKLIST, lines: [MEASURED_READY_LINE] },
            {
                ...MEASUREMENTS,
                lines: [measuredLine(MEASURED_READY_LINE, PASS_MEASUREMENT, { problems: ['measurement_contradicted'] })]
            }
        );

        // The view decides; the route only shows. A second verdict would be a second authority.
        expect(button('submit-checklist').disabled).toBe(false);
        expect(has('[data-testid="submit-blocked"]')).toBe(false);
    });

    it('highlights the lines a submission is refused for as contradicted, in the reader words', async () => {
        await start(
            'USER',
            { ...READY_CHECKLIST, lines: [MEASURED_READY_LINE] },
            { ...MEASUREMENTS, lines: [MEASUREMENTS.lines[0]] }
        );

        click('submit-checklist');
        refuse(http.expectOne({ method: 'POST', url: `${BASE}/2/submission` }), 'checklist-measurement-contradicted', [
            {
                itemId: 101,
                position: 1,
                answer: 'yes',
                outcome: 'fail',
                reason: null,
                submittedOutcome: null,
                submittedReason: null
            }
        ]);
        expect(text('[data-testid="refusal-message"]')).toBe(
            'Line(s) 1 are answered yes where the measurement is not met, and the submission is refused. Answer them as measured, or settle the findings through triage: a false positive leaves the figures once it is settled.'
        );
        expect(text('[data-testid="measured-conflict-1"]')).toBe(
            'Refused by its measurement Answered Yes, measured Not met'
        );
        expect(dom().querySelector('[data-testid="line-1"]')?.classList.contains('border-2')).toBe(true);
        measurementsRead().flush(MEASUREMENTS);
    });

    it('highlights the lines a sign-off is refused for, with what the submission had found', async () => {
        const submitted = { ...SUBMITTED_CHECKLIST, lines: [MEASURED_READY_LINE] };
        await start('ADMIN', submitted, {
            ...MEASUREMENTS,
            status: 'submitted',
            lines: [measuredLine(MEASURED_READY_LINE, PASS_MEASUREMENT, { atSubmission: PASS_MEASUREMENT })]
        });
        expect(button('sign-off-checklist').disabled).toBe(false);

        click('sign-off-checklist');
        refuse(http.expectOne({ method: 'POST', url: `${BASE}/2/sign-off` }), 'checklist-measurement-changed', [
            {
                itemId: 101,
                position: 1,
                answer: 'yes',
                outcome: 'no_data',
                reason: 'stale',
                submittedOutcome: 'pass',
                submittedReason: null
            }
        ]);
        expect(text('[data-testid="refusal-message"]')).toContain(
            'A measurement changed since the submission — line(s) 1.'
        );
        expect(text('[data-testid="measured-conflict-1"]')).toContain(
            'Answered Yes, measured No data (too old) · Met at the submission'
        );
        measurementsRead().flush(MEASUREMENTS);
    });

    it('greys out a sign-off whose measurement moved since the submission, and says so on the line', async () => {
        const stale = measurement(101, { ruleKind: 'coverage_threshold', reason: 'stale' });
        await start(
            'ADMIN',
            { ...SUBMITTED_CHECKLIST, lines: [MEASURED_READY_LINE] },
            {
                ...MEASUREMENTS,
                status: 'submitted',
                lines: [measuredLine(MEASURED_READY_LINE, stale, { atSubmission: PASS_MEASUREMENT })]
            }
        );

        expect(button('sign-off-checklist').disabled).toBe(true);
        expect(text('[data-testid="sign-off-blocked-measured"]')).toContain('Line(s) 1 are measured otherwise');
        expect(text('[data-testid="changed-since-submission"]')).toBe('Changed since the submission, which found: Met');
    });

    it('shows a signed-off revision with its frozen measurements, and nothing to answer', async () => {
        await start(
            'ADMIN',
            { ...SIGNED_CHECKLIST, lines: [MEASURED_READY_LINE] },
            {
                ...MEASUREMENTS,
                status: 'signed_off',
                live: false,
                computedAt: null,
                lines: [measuredLine(MEASURED_READY_LINE, { ...PASS_MEASUREMENT, id: 88, purpose: 'sign_off' })]
            }
        );

        expect(text('[data-testid="measurements-mode"]')).toBe(
            'Measurements frozen by the sign-off: the evidence as it was judged then, not recomputed over data that has moved since.'
        );
        expect(text('[data-testid="measurement-1"] [data-testid="outcome"]')).toBe('Met');
        expect(has('[id^="answer-measured-"]')).toBe(false);
    });
});

describe('the measured lines, by their rules', () => {
    it('offers yes where met, no where not met, and nothing where there is no data', () => {
        expect(measuredAnswer(MEASUREMENTS.lines[0])).toBe('yes');
        expect(measuredAnswer(measuredLine(MEASURED_OPEN_LINE, FAIL_MEASUREMENT))).toBe('no');
        expect(measuredAnswer(MEASUREMENTS.lines[1])).toBeNull();
        expect(measuredAnswer(null)).toBeNull();
    });

    it('names what moved since a submission', () => {
        const line = measuredLine(MEASURED_READY_LINE, PASS_MEASUREMENT, { atSubmission: PASS_MEASUREMENT });
        const submitted = { ...MEASUREMENTS, status: 'submitted' as const, lines: [line] };
        expect(changedSinceSubmission(submitted)).toEqual([]);
        const moved = {
            ...line,
            measurement: { ...PASS_MEASUREMENT, outcome: 'no_data' as const, reason: 'stale' as const }
        };
        expect(changedSinceSubmission({ ...submitted, lines: [moved] })).toEqual([1]);
        // The reason alone moving is a change: the sign-off compares both.
        const reasoned = {
            ...line,
            atSubmission: NO_DATA_MEASUREMENT,
            measurement: { ...NO_DATA_MEASUREMENT, reason: 'stale' as const }
        };
        expect(changedSinceSubmission({ ...submitted, lines: [reasoned] })).toEqual([1]);
        expect(changedSinceSubmission({ ...submitted, status: 'draft', lines: [moved] })).toEqual([]);
    });

    it('reads the lines a measurement refusal names, and nothing from one that names none it can read', () => {
        const line = {
            itemId: 101,
            position: 1,
            answer: 'yes',
            outcome: 'fail',
            reason: null,
            submittedOutcome: null,
            submittedReason: null
        };
        expect(measuredConflictLinesOf({ error: { lines: [line, { itemId: 'x' }] } })).toEqual([line]);
        expect(measuredConflictLinesOf({ error: { lines: 'no' } })).toBeNull();
        expect(measuredConflictLinesOf({ error: {} })).toBeNull();
    });

    it('words each reason with its own sentence, never another reason’s', () => {
        for (const [reason, key] of Object.entries(NO_DATA_KEYS))
            expect(key).toBe(`project_checklist.reason_${reason}`);
        for (const [reason, key] of Object.entries(NO_DATA_SHORT_KEYS)) {
            expect(key).toBe(`project_checklist.reason_short_${reason}`);
        }
    });

    it('has every mapped key in both bundles — the i18n check cannot see them', () => {
        const lookup = (bundle: unknown, key: string) =>
            key
                .split('.')
                .reduce<unknown>((node, part) => (node as Record<string, unknown> | undefined)?.[part], bundle);
        for (const map of [
            OUTCOME_KEYS,
            NO_DATA_KEYS,
            NO_DATA_SHORT_KEYS,
            LOOK_STATUS_KEYS,
            SOURCE_KEYS,
            RECONCILIATION_KEYS,
            MEASURED_PROBLEM_KEYS,
            AS_MEASURED_SKIP_KEYS
        ]) {
            for (const key of Object.values(map)) {
                expect(typeof lookup(english, key), `${key} in en.json`).toBe('string');
                expect(typeof lookup(french, key), `${key} in fr.json`).toBe('string');
            }
        }
    });
});
