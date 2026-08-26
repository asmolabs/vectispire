import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { Licenses } from './licenses';

/**
 * The licence screen, and the three places it decides rather than displays.
 *
 * **Why this page before the other sixteen without a spec.** Most pages render an HTTP response
 * as it arrived, and a unit test that mounts one only proves the HTTP client works. This one
 * filters, counts and parses a target out of a string — and the figures it produces are the ones
 * somebody quotes in a compliance review, where a wrong number reads as a fact rather than as a
 * bug.
 */
describe('the licence inventory screen', () => {
    let fixture: ComponentFixture<Licenses>;
    let http: HttpTestingController;

    const SUMMARY = {
        totalDependencies: 3,
        uniqueLicenses: 2,
        nonCompliantCount: 2,
        // FORBIDDEN is genuinely absent, which is the point: the template adds it in.
        breakdownByRisk: { PERMISSIVE: 2, WEAK_COPYLEFT: 0, STRONG_COPYLEFT: 1 }
    };

    const entry = (packageName: string, license: string, riskCategory: string, compliant: boolean) => ({
        packageName,
        packageVersion: '1.0.0',
        purl: null,
        license,
        riskCategory,
        compliant,
        violationReason: compliant ? null : 'Disallowed licence',
        targetId: 7,
        targetKind: 'repository',
        targetName: 'ours'
    });

    const INVENTORY = [
        entry('spring-core', 'Apache-2.0', 'PERMISSIVE', true),
        entry('mysql-connector', 'GPL-2.0', 'STRONG_COPYLEFT', false),
        entry('jackson', 'Apache-2.0', 'PERMISSIVE', false)
    ];

    const conflict = (packageName: string, compatibility: string) => ({
        packageName,
        packageVersion: '1.0.0',
        licenseExpression: 'GPL-2.0',
        riskCategory: 'STRONG_COPYLEFT',
        targetKind: 'repository',
        targetName: 'ours',
        compatibility,
        legalRiskExplanation: '',
        remediationAdvice: ''
    });

    const CONFLICTS = [
        conflict('blocking', 'INCOMPATIBLE_BLOCKING'),
        conflict('conditional', 'CONDITIONAL'),
        conflict('fine', 'COMPATIBLE')
    ];

    /** Answers whatever the page asked for on this pass, and hands back the fixtures. */
    function settle(): void {
        http.match((call) => call.url === '/api/v1/repositories').forEach((call) =>
            call.flush([{ id: 7, name: 'ours', displayName: 'Ours', url: 'ssh://git@example.invalid/ours.git', branch: 'main' }]));
        http.match((call) => call.url === '/api/v1/containers').forEach((call) =>
            call.flush([{ id: 3, reference: 'registry.invalid/app:1.0' }]));
        http.match((call) => call.url === '/api/v1/licenses/summary').forEach((call) => call.flush(SUMMARY));
        http.match((call) => call.url === '/api/v1/licenses/inventory').forEach((call) => call.flush(INVENTORY));
        http.match((call) => call.url === '/api/v1/licenses/policy').forEach((call) =>
            call.flush({ disallowedCategories: ['FORBIDDEN'], explicitlyAllowedLicenses: ['Apache-2.0'], explicitlyDisallowedLicenses: ['GPL-2.0'] }));
        http.match((call) => call.url === '/api/v1/licenses/conflicts').forEach((call) => call.flush(CONFLICTS));
    }

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Licenses],
            providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        fixture = TestBed.createComponent(Licenses);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        settle();
    }, 20_000);

    it('counts only the conflicts that block, not every incompatibility', () => {
        // Three conflicts, one of them blocking. Counting all three would tell a release manager
        // to stop shipping over a conditional finding, and counting none would let a real one through.
        expect(fixture.componentInstance.conflicts()).toHaveLength(3);
        expect(fixture.componentInstance.blockingConflictsCount()).toBe(1);
    });

    it('applies the risk and compliance filters together, not one instead of the other', () => {
        const page = fixture.componentInstance;
        expect(page.filteredInventory()).toHaveLength(3);

        page.selectedRisk.set('PERMISSIVE');
        expect(page.filteredInventory().map((entry) => entry.packageName)).toEqual(['spring-core', 'jackson']);

        // Both filters at once is the case worth pinning: `jackson` is permissive *and*
        // non-compliant, so a page that replaced one filter with the other would still return a
        // plausible-looking row and nobody would notice.
        page.selectedCompliance.set('NON_COMPLIANT');
        expect(page.filteredInventory().map((entry) => entry.packageName)).toEqual(['jackson']);
    });

    it('asks the server for the target the operator picked', () => {
        fixture.componentInstance.onTargetChange('repo:7');

        const summary = http.expectOne((call) => call.url === '/api/v1/licenses/summary');
        // The id is parsed out of `repo:7` by hand. Off-by-one in that substring sends the
        // figures of a different repository, which the screen would present as this one's.
        expect(summary.request.params.get('repo_id')).toBe('7');
        expect(summary.request.params.get('container_id')).toBeNull();
        settle();
    });

    it('sends a container id when the target is a container, and never both', () => {
        fixture.componentInstance.onTargetChange('container:3');

        const summary = http.expectOne((call) => call.url === '/api/v1/licenses/summary');
        expect(summary.request.params.get('container_id')).toBe('3');
        expect(summary.request.params.get('repo_id')).toBeNull();
        settle();
    });

    it('renders the strong-copyleft card as a sum, counting an absent category as zero', () => {
        fixture.detectChanges();

        // **The template does arithmetic**, and this is the only assertion that reads it:
        //     {{ (breakdownByRisk['STRONG_COPYLEFT'] ?? 0) + (breakdownByRisk['FORBIDDEN'] ?? 0) }}
        // FORBIDDEN is absent from the fixture on purpose. Without the `?? 0` the sum renders as
        // `NaN` on a compliance figure, and dropping the second term under-reports the licences
        // that block a release.
        const cards = Array.from(
            (fixture.nativeElement as HTMLElement).querySelectorAll('.p-card .text-2xl')
        ).map((node) => node.textContent?.trim());

        // Four headline cards: total, permissive, weak copyleft, then the sum. Read by position
        // rather than by colour class, so a restyle does not silently stop testing anything.
        expect(cards).toEqual(['3', '2', '0', '1']);
    });

    it('offers every target plus an explicit "all", with "all" first', () => {
        const options = fixture.componentInstance.targetOptions();

        expect(options[0].value).toBe('ALL');
        expect(options.map((option) => option.value)).toEqual(['ALL', 'repo:7', 'container:3']);
    });
});
