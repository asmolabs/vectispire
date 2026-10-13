import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { describe, expect, it } from 'vitest';
import { Security } from './security';
import { asSchema } from '@/app/core/testing/contract';
import { useEnglish, useFrench } from '@/app/core/testing/english';

/**
 * The security posture's policy column. It printed the overview's source as sent beside its
 * version — "global v2", "target v4" in the French interface — and "default" alone for the built-in.
 */
describe('the security posture', () => {
    let fixture: ComponentFixture<Security>;

    function target(targetId: number, source: string, version: number | null) {
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

    async function mount(targets: ReturnType<typeof target>[]) {
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
});
