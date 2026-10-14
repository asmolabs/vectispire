import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { useEnglish } from '@/app/core/testing/english';
import { asSchema } from '@/app/core/testing/contract';
import { BlastRadius } from './blast-radius';

/**
 * The explorer's two requests: the ranking it opens on, and the graph of the component picked.
 *
 * <p>They shared one `loading` flag, so whichever answered first switched the spinner off while the
 * other was still on its way; two quick picks showed whichever graph answered last; and a ranking
 * that failed left an overview with no component and no reason. The answers below come back in the
 * order that used to break it.
 */
describe('the blast-radius explorer', () => {
    let fixture: ComponentFixture<BlastRadius>;
    let http: HttpTestingController;

    const TOP = '/api/v1/blast-radius/top-impact';
    const EXPLORE = '/api/v1/blast-radius/explore';

    const top = (packageName: string) =>
        asSchema('TopImpactPackage', {
            packageName,
            ecosystem: 'maven',
            affectedTargetsCount: 3,
            blastRadiusScore: 40,
            directUsages: 1,
            transitiveUsages: 2,
            maxCvss: 7.5,
            totalCves: 1
        });

    const report = (query: string) =>
        asSchema('BlastRadiusReport', {
            query,
            queryType: 'PACKAGE',
            blastRadiusScore: 40,
            directUsages: 1,
            transitiveUsages: 0,
            totalAssociatedCves: 0,
            totalTargetsAffected: 1,
            targets: [],
            graph: {
                nodes: [
                    {
                        id: query,
                        label: `graph of ${query}`,
                        type: 'PACKAGE',
                        isDirect: true,
                        riskScore: 40,
                        cves: [],
                        version: null,
                        ecosystem: null
                    }
                ],
                edges: []
            }
        });

    const page = () => fixture.nativeElement as HTMLElement;
    const analyseButton = () =>
        Array.from(page().querySelectorAll('button')).find((b) => b.textContent.includes('Analyse'))!;

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [BlastRadius],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting()]
        }).compileComponents();
        useEnglish();
        fixture = TestBed.createComponent(BlastRadius);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
    }, 20_000);

    it("shows the graph picked last when the previous pick's answer comes last", () => {
        http.expectOne((call) => call.url === TOP).flush([top('log4j-core'), top('jackson-databind')]);
        fixture.detectChanges();

        fixture.componentInstance.selectQuickPackage('log4j-core');
        fixture.componentInstance.selectQuickPackage('jackson-databind');
        const [first, second] = http.match((call) => call.url === EXPLORE);
        second.flush(report('jackson-databind'));
        // A request still open would deliver the old graph now; a cancelled one cannot.
        if (!first.cancelled) first.flush(report('log4j-core'));
        fixture.detectChanges();

        expect(page().textContent).toContain('graph of jackson-databind');
        expect(page().textContent).not.toContain('graph of log4j-core');
    });

    it('keeps the exploration spinning when the ranking answers first', () => {
        fixture.componentInstance.searchQuery = 'log4j-core';
        fixture.componentInstance.explore();
        http.expectOne((call) => call.url === TOP).flush([top('log4j-core')]);
        fixture.detectChanges();

        // The ranking's answer used to switch the shared flag off: the overview came back and the
        // button stopped spinning while the graph asked for was still on its way.
        expect(page().textContent).not.toContain('Pick a component to see what it reaches');
        expect(page().querySelector('p-progressspinner')).not.toBeNull();
        expect(analyseButton().classList.contains('p-button-loading')).toBe(true);

        http.expectOne((call) => call.url === EXPLORE).flush(report('log4j-core'));
        fixture.detectChanges();
        expect(page().textContent).toContain('graph of log4j-core');
        expect(page().querySelector('p-progressspinner')).toBeNull();
    });

    it("says why the ranking is missing, in the server's words", () => {
        http.expectOne((call) => call.url === TOP).flush(
            { detail: 'The inventory is being rebuilt.', status: 503 },
            { status: 503, statusText: 'Service Unavailable' }
        );
        fixture.detectChanges();

        const message = page().querySelector('[data-testid="top-packages-error"]');
        expect(message?.textContent).toContain('The inventory is being rebuilt.');
    });

    it('falls back on its own sentence when the server gives no reason', () => {
        http.expectOne((call) => call.url === TOP).flush(null, { status: 500, statusText: 'Server Error' });
        fixture.detectChanges();

        const message = page().querySelector('[data-testid="top-packages-error"]');
        expect(message?.textContent).toContain('Could not load the components with the widest reach.');
    });
});
