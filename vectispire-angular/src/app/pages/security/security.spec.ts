import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { RouterLink, provideRouter } from '@angular/router';
import { describe, expect, it } from 'vitest';
import { Security } from './security';
import type { TargetPosture } from '@/app/core/api.models';
import { asSchema } from '@/app/core/testing/contract';
import { useEnglish, useFrench } from '@/app/core/testing/english';

/**
 * The security posture's policy column. It printed the overview's source as sent beside its
 * version — "global v2", "target v4" in the French interface — and "default" alone for the built-in.
 */
describe('the security posture', () => {
    let fixture: ComponentFixture<Security>;

    function target(targetId: number, source: string, version: number | null): TargetPosture {
        return {
            kind: 'repository',
            targetId,
            name: `repo-${targetId}`,
            observation: 'ok',
            observed: true,
            passed: true,
            verdict: { passed: true, evaluated: 3, violations: [], countsBySeverity: {} },
            policy: { source, version },
            lastScanAt: null,
            lastScanId: null
        };
    }

    async function mount(targets: TargetPosture[]) {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Security],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();
        fixture = TestBed.createComponent(Security);
        const http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        http.expectOne('/api/v1/security/overview').flush(
            asSchema('SecurityOverviewView', {
                targets,
                failingCount: 0,
                totalCount: targets.length,
                kevCount: 0,
                neverScannedCount: 0,
                lastScanFailedCount: 0
            })
        );
    }

    /** The policy cell of each row, as a reader sees it. */
    function policies(): (string | undefined)[] {
        return [...(fixture.nativeElement as HTMLElement).querySelectorAll('tbody tr')].map((row) =>
            row.querySelectorAll('td')[3]?.textContent?.replace(/\s+/g, ' ').trim()
        );
    }

    it("names the policy that decided in the reader's language, with its version when it has one", async () => {
        await mount([
            target(1, 'built-in', null),
            target(2, 'global', 2),
            target(3, 'target', 4),
            target(4, 'team', 1)
        ]);

        useEnglish();
        fixture.detectChanges();
        expect(policies().slice(0, 2)).toEqual(['Built-in default', 'Global policy · v2']);

        useFrench();
        fixture.detectChanges();
        expect(policies()).toEqual([
            'Défaut intégré',
            'Politique globale · v2',
            'Politique de la cible · v4',
            'team · v1'
        ]);
    }, 20_000);

    it('words an unobserved target in the reader language, after a switch too, and links to its backlog', async () => {
        await mount([
            {
                ...target(7, 'built-in', null),
                observation: 'never_scanned',
                observed: false,
                passed: false,
                lastScanAt: '2026-08-10 18:45:18.408868',
                verdict: {
                    passed: false,
                    evaluated: 0,
                    countsBySeverity: {},
                    violations: [
                        {
                            rule: 'observation',
                            issueId: null,
                            severity: null,
                            reason: 'Not observed.',
                            identifier: null,
                            package: null
                        }
                    ]
                }
            } as TargetPosture
        ]);
        useEnglish();
        fixture.detectChanges();
        const row = (): HTMLElement => (fixture.nativeElement as HTMLElement).querySelector('tbody tr')!;
        const badges = () => [...row().querySelectorAll('p-tag')].map((tag) => tag.textContent.trim());
        const reason = () => row().querySelector('[data-testid="violation-reason"]')?.textContent?.trim();
        expect(badges()).toEqual(['Failing', 'Never scanned']);
        expect(reason()).toMatch(/^No scan of this target has completed/);
        // Shown in the reader's time zone, day first: the hour is the machine's, the pattern is not.
        expect(row().querySelectorAll('td')[4].textContent.trim()).toMatch(/^1[01]\/08\/2026 \d\d:\d5$/);
        // A `p-button` carries the link, not an anchor: read the tree its RouterLink would navigate to.
        const link = fixture.debugElement.query(By.directive(RouterLink)).injector.get(RouterLink);
        expect(link.urlTree?.toString()).toBe('/issues?repository_id=7');

        useFrench();
        fixture.detectChanges();
        expect(badges()).toEqual(['Non conforme', 'Jamais analysé']);
        expect(reason()).toMatch(/^Aucune analyse de cette cible n'a abouti/);
    });

    it('says a failed export above the table it was asked from', async () => {
        // The export wrote to the error the page shows only without an overview: once the table
        // had loaded, a failed download said nothing at all.
        await mount([target(1, 'global', 2)]);
        useEnglish();
        fixture.detectChanges();
        [...(fixture.nativeElement as HTMLElement).querySelectorAll('button')]
            .find((button) => button.textContent.trim() === 'CSV')!
            .click();
        TestBed.inject(HttpTestingController)
            .expectOne('/api/v1/targets/repository/1/issues.csv')
            .flush(new Blob(['{}']), { status: 500, statusText: 'Internal Server Error' });
        fixture.detectChanges();

        expect(
            (fixture.nativeElement as HTMLElement).querySelector('[data-testid="export-error"]')?.textContent
        ).toContain('The export could not be produced.');
    }, 20_000);

    it('shows a failed overview in the server’s words', async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Security],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();
        fixture = TestBed.createComponent(Security);
        fixture.detectChanges();
        TestBed.inject(HttpTestingController)
            .expectOne('/api/v1/security/overview')
            .flush(
                { title: 'Internal Server Error', status: 500, detail: 'Posture is being recomputed.' },
                { status: 500, statusText: 'Internal Server Error' }
            );
        fixture.detectChanges();

        expect((fixture.nativeElement as HTMLElement).textContent).toContain('Posture is being recomputed.');
    }, 20_000);
});
