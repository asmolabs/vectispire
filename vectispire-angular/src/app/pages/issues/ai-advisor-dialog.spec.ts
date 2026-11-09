import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import type { AiVulnerabilityAdvice, Issue } from '@/app/core/api.models';
import { backlogEntry } from '@/app/core/testing/issues.fixtures';
import { AiAdvisorDialog } from './ai-advisor-dialog';
import { vulnerabilityAdvice as advice } from '@/app/core/testing/intel.fixtures';
import { mountOnIssues } from './issues-page.testing';

/**
 * The advisor's dialog, on its own: a model that does not answer said as such — the branch that did
 * not exist — and the suggestion handed to the triage dialog with the issue it was asked about.
 */
describe("the advisor's dialog", () => {
    afterEach(() => TestBed.resetTestingModule());

    const issue = backlogEntry(11);
    const explain = '/api/v1/ai-advisor/explain/issue/11';

    it('says the model did not answer, and stops waiting', () => {
        const { fixture, http } = mountOnIssues(AiAdvisorDialog, { issues: [issue] });
        fixture.componentInstance.openAiAdvisor(issue);
        http.expectOne((call) => call.url === explain).flush(null, { status: 502, statusText: 'Bad Gateway' });
        fixture.detectChanges();
        expect(fixture.componentInstance.aiAdviceLoading()).toBe(false);
        expect(document.body.textContent).toContain('The model did not answer.');
    });

    it('hands its suggestion and the issue on, and closes', () => {
        const { fixture, http } = mountOnIssues(AiAdvisorDialog, { issues: [issue] });
        const handed: { issue: Issue; advice: AiVulnerabilityAdvice }[] = [];
        fixture.componentInstance.apply.subscribe((one) => handed.push(one));
        fixture.componentInstance.openAiAdvisor(issue);
        http.expectOne((call) => call.url === explain).flush(advice('not_affected'));
        fixture.componentInstance.applySuggestedVex();
        expect(handed.map((one) => [one.issue.id, one.advice.vexSuggestion.status])).toEqual([[11, 'not_affected']]);
        expect(fixture.componentInstance.aiModalOpen()).toBe(false);
    });
});
