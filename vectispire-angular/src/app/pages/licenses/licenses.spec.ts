import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { Licenses } from './licenses';
import { SessionStore } from '@/app/core/session.store';
import { asSchema, asSchemaList } from '@/app/core/testing/contract';

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

    const SUMMARY = asSchema('LicenseSummary', {
        totalDependencies: 3,
        uniqueLicenses: 2,
        nonCompliantCount: 2,
        // FORBIDDEN is genuinely absent, which is the point: the template adds it in.
        breakdownByRisk: { PERMISSIVE: 2, WEAK_COPYLEFT: 0, STRONG_COPYLEFT: 1 }
    });

    const entry = (packageName: string, license: string, riskCategory: string, compliant: boolean) =>
        asSchema('LicenseEntry', {
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

    const conflict = (packageName: string, compatibility: string) =>
        asSchema('LicenseConflict', {
            packageName,
            packageVersion: '1.0.0',
            licenseExpression: 'GPL-2.0',
            riskCategory: 'STRONG_COPYLEFT',
            targetKind: 'repository',
            targetName: 'ours',
            compatibility,
            verdict: 'PERMISSIVE'
        });

    const CONFLICTS = [
        conflict('blocking', 'INCOMPATIBLE_BLOCKING'),
        conflict('conditional', 'CONDITIONAL'),
        conflict('fine', 'COMPATIBLE')
    ];

    /** Answers whatever the page asked for on this pass, and hands back the fixtures. */
    function settle(): void {
        http.match((call) => call.url === '/api/v1/repositories').forEach((call) =>
            call.flush(
                asSchemaList('RepositorySummary', [
                    {
                        id: 7,
                        name: 'ours',
                        displayName: 'Ours',
                        url: 'ssh://git@example.invalid/ours.git',
                        branch: 'main',
                        openIssues: 0
                    }
                ])
            )
        );
        http.match((call) => call.url === '/api/v1/containers').forEach((call) =>
            call.flush(
                asSchemaList('ContainerSummary', [{ id: 3, reference: 'registry.invalid/app:1.0', openIssues: 0 }])
            )
        );
        http.match((call) => call.url === '/api/v1/licenses/summary').forEach((call) => call.flush(SUMMARY));
        http.match((call) => call.url === '/api/v1/licenses/inventory').forEach((call) => call.flush(INVENTORY));
        http.match((call) => call.url === '/api/v1/licenses/policy').forEach((call) =>
            call.flush(
                asSchema('LicensePolicy', {
                    disallowedCategories: ['FORBIDDEN'],
                    explicitlyAllowedLicenses: ['Apache-2.0'],
                    explicitlyDisallowedLicenses: ['GPL-2.0']
                })
            )
        );
        http.match((call) => call.url === '/api/v1/licenses/conflicts').forEach((call) => call.flush(CONFLICTS));
    }

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Licenses],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        // A security lead: it is the role the server requires in order to write the policy, and the
        // screen must not offer the button to anybody else.
        TestBed.inject(SessionStore).open('a-token', {
            username: 'ciso',
            displayName: null,
            role: 'CISO',
            mustChangePassword: false,
            mfaEnabled: false
        });

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
        const cards = Array.from((fixture.nativeElement as HTMLElement).querySelectorAll('.p-card .text-2xl')).map(
            (node) => node.textContent?.trim()
        );

        // Four headline cards: total, permissive, weak copyleft, then the sum. Read by position
        // rather than by colour class, so a restyle does not silently stop testing anything.
        expect(cards).toEqual(['3', '2', '0', '1']);
    });

    it('offers every target plus an explicit "all", with "all" first', () => {
        const options = fixture.componentInstance.targetOptions();

        expect(options[0].value).toBe('ALL');
        expect(options.map((option) => option.value)).toEqual(['ALL', 'repo:7', 'container:3']);
    });

    it('sends the policy as the form carries it, lists cleaned up', () => {
        const page = fixture.componentInstance;
        page.editPolicy();

        // Pre-filled from what exists: starting from an empty form would make every save an erasure
        // of the rule in place.
        expect(page.draftDisallowed).toEqual(['FORBIDDEN']);
        expect(page.draftAllowedLicenses).toBe('Apache-2.0');

        page.toggleCategory('STRONG_COPYLEFT', true);
        page.draftDisallowedLicenses = 'GPL-2.0, , AGPL-3.0  ';
        page.savePolicy();

        const call = http.expectOne((request) => request.method === 'PUT' && request.url === '/api/v1/licenses/policy');
        // A trailing comma is how one types a list, not a licence named "".
        expect(call.request.body).toEqual({
            disallowedCategories: ['FORBIDDEN', 'STRONG_COPYLEFT'],
            explicitlyAllowedLicenses: ['Apache-2.0'],
            explicitlyDisallowedLicenses: ['GPL-2.0', 'AGPL-3.0']
        });
        call.flush(
            asSchema('LicensePolicy', {
                disallowedCategories: ['FORBIDDEN', 'STRONG_COPYLEFT'],
                explicitlyAllowedLicenses: ['Apache-2.0'],
                explicitlyDisallowedLicenses: ['GPL-2.0', 'AGPL-3.0']
            })
        );

        expect(page.editingPolicy()).toBe(false);
        expect(page.policy()?.disallowedCategories).toContain('STRONG_COPYLEFT');

        // **And the whole screen is reloaded.** Every row's compliance has just been recomputed by
        // the server; keeping the inventory as it stands would show yesterday's verdict under
        // today's policy.
        expect(http.match((request) => request.url === '/api/v1/licenses/inventory')).toHaveLength(1);
        settle();
    });

    it('unticks one category without touching the others', () => {
        const page = fixture.componentInstance;
        page.editPolicy();
        page.toggleCategory('STRONG_COPYLEFT', true);
        page.toggleCategory('FORBIDDEN', false);

        expect(page.draftDisallowed).toEqual(['STRONG_COPYLEFT']);
        expect(page.isDisallowed('FORBIDDEN')).toBe(false);
    });

    it('garde le formulaire ouvert et dit pourquoi quand le serveur refuse', () => {
        const page = fixture.componentInstance;
        page.editPolicy();
        page.savePolicy();

        http.expectOne((request) => request.method === 'PUT' && request.url === '/api/v1/licenses/policy').flush(
            { message: 'Forbidden.' },
            { status: 403, statusText: 'Forbidden' }
        );

        expect(page.editingPolicy()).toBe(true);
        expect(page.policyError()).toContain('Forbidden.');
    });

    it('does not offer the edit to an account that governs nothing', () => {
        TestBed.inject(SessionStore).open('a-token', {
            username: 'reader',
            displayName: null,
            role: 'USER',
            mustChangePassword: false,
            mfaEnabled: false
        });
        fixture.detectChanges();

        // The server requires the security lead; offering the button to anybody else would be
        // offering a door it closes.
        expect(fixture.componentInstance.canEditPolicy()).toBe(false);
    });
});
