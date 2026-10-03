import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { Project } from './project';
import { SessionStore } from '@/app/core/session.store';
import { useEnglish } from '@/app/core/testing/english';
import {
    COMPLETE_COMPONENTS,
    NO_DATA_SUMMARY,
    PROJECT_COMPLIANCE,
    PROJECT_COMPONENTS,
    PROJECT_DETAIL,
    PROJECT_ID,
    SCORECARD_NO_DATA
} from '@/app/core/testing/scopes.fixtures';

/**
 * A project's page, through the DOM: what a reader sees is what is asserted, because each of these
 * can be right in the component and wrong on screen — a partial marker that is computed and never
 * drawn reads as the whole project, a NO_DATA verdict drawn as "0%" reads as a failure, a component
 * list without its "incomplete" banner reads as a clean inventory.
 */
describe('the project page', () => {
    let fixture: ComponentFixture<Project>;
    let http: HttpTestingController;

    const BASE = `/api/v1/projects/${PROJECT_ID}`;

    interface Answers {
        detail?: object | 'not-found';
        compliance?: object | 'not-found';
        components?: object | 'not-found';
    }

    function answer(url: string, body: object | 'not-found'): void {
        const request = http.expectOne({ method: 'GET', url });
        if (body === 'not-found') {
            request.flush(
                { type: 'about:blank', title: 'Not Found', status: 404, detail: 'Project not found.' },
                { status: 404, statusText: 'Not Found' }
            );
        } else {
            request.flush(body);
        }
    }

    async function open(given: Answers = {}): Promise<void> {
        TestBed.inject(SessionStore).open('a-token', {
            username: 'reader',
            displayName: null,
            role: 'USER',
            mustChangePassword: false,
            mfaEnabled: false
        });
        useEnglish();
        fixture = TestBed.createComponent(Project);
        fixture.componentRef.setInput('projectId', String(PROJECT_ID));
        http = TestBed.inject(HttpTestingController);
        fixture.autoDetectChanges();
        await fixture.whenStable();
        answer(BASE, given.detail ?? PROJECT_DETAIL);
        answer(`${BASE}/compliance`, given.compliance ?? PROJECT_COMPLIANCE);
        answer(`${BASE}/components`, given.components ?? PROJECT_COMPONENTS);
        await fixture.whenStable();
    }

    const dom = () => fixture.nativeElement as HTMLElement;
    const text = (selector: string) => dom().querySelector(selector)?.textContent?.replace(/\s+/g, ' ').trim() ?? '';
    const has = (selector: string) => dom().querySelector(selector) !== null;

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Project],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();
    }, 20_000);

    it('heads the page with the project, its solution, its counts and languages, and links its open issues unsettled', async () => {
        await open();

        expect(text('[data-testid="project-title"]')).toBe('Gateway');
        expect(text('[data-testid="project-solution"]')).toBe('In the solution Payments');
        const header = text('[data-testid="project-header"]');
        expect(header).toContain('Repositories: 1');
        expect(text('[data-testid="container-count"]')).toContain('1');
        expect(text('[data-testid="project-languages"]')).toContain('java');
        expect(text('[data-testid="project-languages"]')).toContain('typescript');

        // The figure leaves settled triage out; the list it opens must too, or the two disagree.
        const issues = dom().querySelector('[data-testid="project-issues"]');
        expect(issues?.textContent).toContain('Open issues: 3');
        expect(issues?.getAttribute('href')).toBe(`/issues?project_id=${PROJECT_ID}&unsettled=true`);
    });

    it('marks a partly visible project in the words the tree uses', async () => {
        await open();

        expect(text('[data-testid="partial"]')).toBe('Partially visible: 1 repositories and 1 images you can see');
        expect(text('[data-testid="scope-partial"]')).toContain('cover only the repositories and images you can see');
    });

    it('says nothing of partial for a project seen whole', async () => {
        await open({
            detail: { ...PROJECT_DETAIL, partial: false },
            compliance: { ...PROJECT_COMPLIANCE, partial: false }
        });

        expect(has('[data-testid="partial"]')).toBe(false);
        expect(has('[data-testid="scope-partial"]')).toBe(false);
    });

    it('asks no report of a project seen in part, and says reports need the whole project', async () => {
        await open();

        expect(text('[data-testid="reports-partial"]')).toContain('only for an account that sees the whole project');
        expect(has('app-project-reports')).toBe(false);
        // Every report route answers 404 to a partial reader: not asked at all.
        http.expectNone(`${BASE}/reports`);
        http.expectNone(`${BASE}/report-plugins`);
    });

    it('opens the reports section for a project seen whole', async () => {
        await open({ detail: { ...PROJECT_DETAIL, partial: false } });

        expect(has('[data-testid="reports-partial"]')).toBe(false);
        expect(has('app-project-reports')).toBe(true);
        http.expectOne({ method: 'GET', url: `${BASE}/report-plugins` }).flush([]);
        http.expectOne({ method: 'GET', url: `${BASE}/reports` }).flush([]);
    });

    it('links the checklist only when the server says it would open', async () => {
        await open();
        expect(has('[data-testid="project-checklist"]')).toBe(false);
    });

    it('links the checklist when checklistsVisible', async () => {
        await open({ detail: { ...PROJECT_DETAIL, checklistsVisible: true } });
        expect(dom().querySelector('[data-testid="project-checklist"]')?.getAttribute('href')).toBe(
            `/projects/${PROJECT_ID}/checklist`
        );
    });

    it('draws the scope compliance: the score and grade, the target count, the verdicts in words', async () => {
        await open();

        expect(text('[data-testid="scorecard-score"]')).toBe('54/100');
        expect(text('[data-testid="scorecard-grade"]')).toBe('Grade D');
        // The scope's risk points, and the target its grade is read from (decision 0036).
        expect(text('[data-testid="scorecard-risk-points"]')).toContain('40.5 risk points');
        expect(text('[data-testid="scorecard-weakest"]')).toContain('Graded by its weakest target, api-gateway');
        expect(text('[data-testid="scorecard-weakest"]')).toContain('Grade D');
        expect(text('[data-testid="scorecard-weakest"]')).toContain('54/100');
        expect(text('[data-testid="scope-target-count"]')).toBe('Computed over 2 targets.');
        expect(text('[data-testid="framework-NIS_2"]')).toContain('72%');
        expect(text('[data-testid="framework-NIS_2"]')).toContain('Partial');
        expect(dom().querySelectorAll('[data-testid="matrix-row"]')).toHaveLength(1);
        expect(text('[data-testid="matrix-row"]')).toContain('api-gateway');
        // The estate's "inspect" narrows the estate page; nothing here can be narrowed.
        expect(text('[data-testid="matrix-row"]')).not.toContain('Inspect');
    });

    it('draws a scope where nothing was scanned as no data — a dash, never a zero or a grade', async () => {
        await open({
            compliance: { ...PROJECT_COMPLIANCE, compliance: NO_DATA_SUMMARY, scorecard: SCORECARD_NO_DATA }
        });

        const nis2 = text('[data-testid="framework-NIS_2"]');
        expect(nis2).toContain('—');
        expect(nis2).toContain('No data');
        expect(nis2).not.toContain('0%');
        expect(text('[data-testid="scorecard-score"]')).toBe('—');
        expect(text('[data-testid="scorecard-grade"]')).toBe('No data');
        // No figure of a grade that does not exist, and no target to read it from.
        expect(has('[data-testid="scorecard-risk-points"]')).toBe(false);
        expect(has('[data-testid="scorecard-weakest"]')).toBe(false);
    });

    it('lists the merged components with their carriers, and filters them by name', async () => {
        await open();

        const rows = () => [...dom().querySelectorAll('[data-testid="component-row"]')];
        expect(rows()).toHaveLength(2);
        expect(rows()[0].textContent).toContain('jackson-databind');
        expect(rows()[0].querySelector('[data-testid="carriers"]')?.textContent).toContain('api-gateway');

        const filter = dom().querySelector<HTMLInputElement>('#component-filter')!;
        filter.value = 'lod';
        filter.dispatchEvent(new Event('input'));
        await fixture.whenStable();
        expect(rows()).toHaveLength(1);
        expect(rows()[0].textContent).toContain('lodash');
        expect(text('[data-testid="component-count"]')).toBe('1 of 2');
    });

    it('says the list is incomplete while a visible target was never scanned, and shows that target as such', async () => {
        await open();

        expect(text('[data-testid="incomplete"]')).toContain('Incomplete list: 1 target listed no components');
        expect(text('[data-testid="inventory-container-4"] [data-testid="inventory-state"]')).toBe('Never scanned');
        expect(text('[data-testid="inventory-repository-9"] [data-testid="inventory-state"]')).toBe('2 components');
    });

    it('draws no banner over a complete list', async () => {
        await open({ components: COMPLETE_COMPONENTS });
        expect(has('[data-testid="incomplete"]')).toBe(false);
    });

    it('saves the CycloneDX document through the client as a blob, under the name the server gave', async () => {
        await open();

        const saved: string[] = [];
        const original = HTMLAnchorElement.prototype.click;
        HTMLAnchorElement.prototype.click = function (this: HTMLAnchorElement) {
            saved.push(this.download);
        };
        try {
            dom().querySelector<HTMLButtonElement>('#download-cyclonedx button')!.click();
            const request = http.expectOne({
                method: 'GET',
                url: `/api/v1/cyclonedx/projects/${PROJECT_ID}/cyclonedx-vex.json`
            });
            expect(request.request.responseType).toBe('blob');
            request.flush(new Blob(['{"bomFormat":"CycloneDX"}']), {
                headers: { 'Content-Disposition': 'attachment; filename="gateway-cyclonedx-vex.json"' }
            });
        } finally {
            HTMLAnchorElement.prototype.click = original;
        }
        expect(saved).toEqual(['gateway-cyclonedx-vex.json']);
    });

    it('renders an empty project: no target, no component, nothing measured', async () => {
        await open({
            detail: {
                ...PROJECT_DETAIL,
                partial: false,
                repositoryCount: 0,
                containerCount: 0,
                repositories: [],
                containers: [],
                detectedLanguages: []
            },
            compliance: {
                ...PROJECT_COMPLIANCE,
                partial: false,
                targetCount: 0,
                compliance: { ...NO_DATA_SUMMARY, totalMonitoredTargets: 0 },
                scorecard: { ...SCORECARD_NO_DATA, totalTargets: 0 }
            },
            components: { ...PROJECT_COMPONENTS, partial: false, complete: true, targets: [], components: [] }
        });

        expect(has('[data-testid="project-languages"]')).toBe(false);
        expect(has('[data-testid="incomplete"]')).toBe(false);
        expect(text('[data-testid="no-components"]')).toBe('No component.');
        expect(text('[data-testid="scorecard-score"]')).toBe('—');
    });

    it("reads no data off the scorecard's own grade, not off the compliance summary beside it", async () => {
        // Measured compliance, a no-data card: the dash is the card's answer, which the repository
        // dialog — with no compliance summary to lean on — reads the same way.
        await open({ compliance: { ...PROJECT_COMPLIANCE, scorecard: SCORECARD_NO_DATA } });

        expect(text('[data-testid="scorecard-score"]')).toBe('—');
        expect(text('[data-testid="scorecard-grade"]')).toBe('No data');
        expect(text('[data-testid="framework-NIS_2"]')).toContain('72%');
    });

    it('shows the not-found state for a project that does not exist or that the reader sees nothing of', async () => {
        await open({ detail: 'not-found', compliance: 'not-found', components: 'not-found' });

        expect(text('[data-testid="not-found"]')).toBe(
            'This project does not exist, or you see none of its repositories and images.'
        );
        expect(has('[data-testid="project-header"]')).toBe(false);
        expect(has('[data-testid="project-components"]')).toBe(false);
    });
});
