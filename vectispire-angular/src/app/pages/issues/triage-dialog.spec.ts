import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import type { TriageRequest } from '@/app/core/api.models';
import { backlogEntry } from '@/app/core/testing/issues.fixtures';
import { TriageDialog } from './triage-dialog';
import { vulnerabilityAdvice as advice } from '@/app/core/testing/intel.fixtures';
import { mountOnIssues } from './issues-page.testing';

/**
 * The triage dialog, on its own: the VEX rules as the API applies them — a justification for "not
 * affected", a review date for a risk accepted — said by the form before anything is sent, a decision
 * sent from a submit, and an advisor's suggestion read in the screen's vocabulary.
 */
describe('the triage dialog', () => {
    afterEach(() => TestBed.resetTestingModule());

    const issue = backlogEntry(11);

    function open() {
        const mounted = mountOnIssues(TriageDialog, { issues: [issue] });
        mounted.fixture.componentInstance.openTriage(issue);
        mounted.fixture.detectChanges();
        return mounted;
    }

    const form = () => document.querySelector<HTMLFormElement>('form#triage-form')!;
    /** The draft's fields change through the dialog's own controls, whose events mark it for a redraw. */
    const redraw = (fixture: {
        componentRef: { changeDetectorRef: { markForCheck(): void } };
        detectChanges(): void;
    }) => {
        fixture.componentRef.changeDetectorRef.markForCheck();
        fixture.detectChanges();
    };

    it('requires a justification for not affected, and is a form that says so', () => {
        const { fixture } = open();
        const dialog = fixture.componentInstance;
        dialog.chooseTriageStatus('not_affected');
        redraw(fixture);
        expect(form()).not.toBeNull();
        expect(document.querySelector('#triage-justification')).not.toBeNull();
        expect(dialog.canSubmitTriage()).toBe(false);
        dialog.triageJustification = 'vulnerable_code_not_present';
        expect(dialog.canSubmitTriage()).toBe(true);
    });

    it('requires a review date for a risk accepted, and drops a justification it cannot carry', () => {
        const { fixture } = open();
        const dialog = fixture.componentInstance;
        dialog.triageJustification = 'component_not_present';
        dialog.chooseTriageStatus('will_not_fix');
        redraw(fixture);
        expect(dialog.triageJustification).toBeNull();
        expect(document.querySelector<HTMLInputElement>('#triage-expires')!.required).toBe(true);
        expect(dialog.canSubmitTriage()).toBe(false);
        dialog.triageExpiresInDays = 90;
        expect(dialog.canSubmitTriage()).toBe(true);
    });

    it('sends the decision on a submit, and says it is decided', () => {
        const { fixture, http } = open();
        let decided = 0;
        fixture.componentInstance.decided.subscribe(() => decided++);
        fixture.componentInstance.chooseTriageStatus('affected');
        redraw(fixture);
        form().dispatchEvent(new Event('submit'));

        const sent = http.expectOne('/api/v1/issues/11/triage');
        expect((sent.request.body as TriageRequest).status).toBe('affected');
        sent.flush(null);
        expect(decided).toBe(1);
        expect(fixture.componentInstance.triageOpen()).toBe(false);
    });

    it('reads an investigation the advisor suggests as under review', () => {
        const { fixture } = mountOnIssues(TriageDialog, { issues: [issue] });
        fixture.componentInstance.applySuggestion(issue, advice('under_investigation'));
        expect(fixture.componentInstance.triageStatus).toBe('under_review');
        expect(fixture.componentInstance.triageComment).toContain('Reachable.');
    });
});
