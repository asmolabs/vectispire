import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
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
