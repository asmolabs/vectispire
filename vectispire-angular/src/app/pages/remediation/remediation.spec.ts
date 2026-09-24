import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { I18nService } from '@/app/core/i18n/i18n.service';
import type { HighImpactFix, RemediationCoverage } from '@/app/core/api.models';
import { Remediation } from './remediation';
import { asSchema } from '@/app/core/testing/contract';

/**
 * The work order.
 *
 * <p>Three things must hold, without which the page advises badly — which is worse than staying
 * quiet. The server's order must be the screen's; an upgrade with no known fixed version must be
 * said differently from an available upgrade; and an unavailable debt figure must not carry away
 * the plan, which is the page's subject.
 */
describe('the remediation plan', () => {
    let fixture: ComponentFixture<Remediation>;
    let http: HttpTestingController;

    const fix = (over: Partial<HighImpactFix>): HighImpactFix =>
        asSchema('HighImpactFix', {
            packageName: 'log4j-core',
            currentVersion: '2.14.1',
            recommendedVersion: '2.17.1',
            cveCountResolved: 3,
            criticalCveCount: 1,
            highCveCount: 2,
            estimatedHours: 1.3,
            leverageScore: 10.4,
            affectedCves: ['CVE-2021-44228'],
            affectedTargetNames: ['alpha'],
            ...over
        });

    beforeEach(async () => {
        await TestBed.configureTestingModule({
            imports: [Remediation],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        // With no dictionary, the pipe renders the key: an assertion about "no fixed version"
        // would then prove nothing about what a reader sees.
        TestBed.inject(I18nService).translations.set({
            common: { loading: 'Chargement…' },
            severities: { critical: 'critiques' },
            remediation: {
                title: 'Plan de remédiation', subtitle: '—', open_findings: 'constats ouverts',
                critical: 'critiques', person_days: 'jours-personne', closed_by_plan: 'fermés',
                empty_title: 'Rien à monter de version.', empty_help: '—',
                no_fixed_version: 'Aucune version corrigée publiée', closes: 'ferme',
                targets: 'cibles', leverage: 'levier', details: 'Détail',
                cves: 'Vulnérabilités fermées', affected_targets: 'Cibles concernées',
                plan_total: 'Total du plan :',
                coverage_title: 'Ce que ce plan ne referme pas',
                coverage_summary: '{{covered}} des {{open}} constats ouverts se ferment par une montée de version. Les {{beyond}} autres se referment autrement :',
                coverage_all: 'Les {{open}} constats ouverts se ferment tous par une montée de version.',
                gap_secret: 'secrets exposés — à révoquer et à faire tourner ; on ne met pas un secret à jour.',
                gap_unpackaged: "vulnérabilités dont aucun paquet n'est nommé — il n'y a rien à monter.",
                gap_other: "constats d'un autre type."
            }
        });

        http = TestBed.inject(HttpTestingController);
        fixture = TestBed.createComponent(Remediation);
        fixture.detectChanges();
    });

    /** The plan, the debt, the admission and the two target lists — in the order the page asks for them. */
    function answer(
        fixes: HighImpactFix[],
        debt: Record<string, unknown> = { totalOpenIssues: 9 },
        coverage: RemediationCoverage | null = null): void {

        plan().flush(fixes);
        http.expectOne((request) => request.url.includes('/remediation/debt')).flush(debt);

        // The admission is optional in these runs: cases that are not about it must be able to
        // ignore it, exactly as the page does when the server does not answer.
        const admission = http.expectOne((request) => request.url.includes('/remediation/coverage'));
        if (coverage) {
            admission.flush(coverage);
        } else {
            admission.error(new ProgressEvent('failed'));
        }

        for (const request of http.match((r) => r.url.includes('/repositories') || r.url.includes('/containers'))) {
            request.flush([]);
        }
        fixture.detectChanges();
    }

    /** The plan request, whatever parameters it carries. */
    function plan() {
        return http.expectOne((request) => request.url.includes('/remediation/high-impact-fixes'));
    }

    it("garde l'ordre du serveur, qui est le classement par levier", () => {
        answer([
            fix({ packageName: 'log4j-core', leverageScore: 10.4 }),
            fix({ packageName: 'openssl', leverageScore: 3.2 })
        ], { totalOpenIssues: 9, criticalIssues: 2 });

        // **The order is the information.** A page that ranks by leverage and then reorders by
        // name, or that a `track` would shuffle, turns a work order into a list.
        const text = fixture.nativeElement.textContent as string;
        expect(text.indexOf('log4j-core')).toBeLessThan(text.indexOf('openssl'));
        expect(text).toContain('2.14.1');
        expect(text).toContain('2.17.1');
    });

    it('says no version fixes it, instead of advising an upgrade that does not exist', () => {
        // **The defect this closes, one step further along.** The server returned the string
        // "latest-patch" for everybody, and the dashboard showed it behind an arrow. Now that it
        // can return nothing, the screen has to say what.
        answer([fix({ recommendedVersion: null as unknown as string })], { totalOpenIssues: 1 });

        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('Aucune version corrigée publiée');
        expect(text).not.toContain('latest-patch');
    });

    it('survives an unavailable debt figure, because the plan is the subject', () => {
        plan().flush([fix({})]);
        http.expectOne((request) => request.url.includes('/remediation/debt'))
            .error(new ProgressEvent('failed'));
        http.expectOne((request) => request.url.includes('/remediation/coverage'))
            .error(new ProgressEvent('failed'));
        for (const request of http.match((r) => r.url.includes('/repositories') || r.url.includes('/containers'))) {
            request.flush([]);
        }
        fixture.detectChanges();

        expect(fixture.nativeElement.textContent).toContain('log4j-core');
        expect(fixture.componentInstance.error()).toBeNull();
    });

    it('asks for more in steps, without passing the ceiling', () => {
        answer(Array.from({ length: 10 }, (_, index) => fix({ packageName: `pkg-${index}` })));

        // Ten returned out of ten asked for: there may be more, so the button is there.
        expect(fixture.componentInstance.mayHaveMore()).toBe(true);
        fixture.componentInstance.showMore();
        fixture.detectChanges();

        // **The step is passed to the server**, without which the button would reload the same ten
        // rows and the screen would look stuck.
        const second = plan();
        expect(second.request.params.get('limit')).toBe('25');
        second.flush(Array.from({ length: 25 }, (_, index) => fix({ packageName: `pkg-${index}` })));
        http.expectOne((request) => request.url.includes('/remediation/debt')).flush({ totalOpenIssues: 9 });
        http.expectOne((request) => request.url.includes('/remediation/coverage'))
            .error(new ProgressEvent('failed'));
        fixture.detectChanges();

        expect(fixture.componentInstance.wanted()).toBe(25);
    });

    it('recharge sur la cible choisie, et repart au premier palier', () => {
        answer([fix({})]);
        fixture.componentInstance.wanted.set(25);

        fixture.componentInstance.scope = 'repo:7';
        fixture.componentInstance.changeScope();

        // The scope is passed to the server, and the size goes back to ten: the plan is no longer
        // the same, and keeping the previous step would suggest a continuity that does not exist.
        const scoped = plan();
        expect(scoped.request.params.get('repoId')).toBe('7');
        expect(scoped.request.params.get('limit')).toBe('10');
        scoped.flush([]);
        http.expectOne((request) => request.url.includes('/remediation/debt')).flush({ totalOpenIssues: 0 });

        // **The scope is passed to the admission too.** A whole-estate admission placed under one
        // repository's plan would say "four hundred left" beneath a list covering three.
        const admission = http.expectOne((request) => request.url.includes('/remediation/coverage'));
        expect(admission.request.params.get('repoId')).toBe('7');
        admission.error(new ProgressEvent('failed'));
        fixture.detectChanges();

        expect(fixture.componentInstance.wanted()).toBe(10);
    });

    it('says why a single action faces a heavy backlog', () => {
        // **The usage report that prompted this panel.** One action, hundreds of open findings:
        // the calculation is right and the screen looked broken. It must now name what does not
        // close by a version bump, and by which move it does close.
        answer([fix({})], { totalOpenIssues: 412 }, {
            openFindings: 412,
            addressableByUpgrade: 12,
            beyondUpgrades: 400,
            gaps: [{ family: 'secret', findings: 399 }, { family: 'unpackaged', findings: 1 }]
        });

        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('Ce que ce plan ne referme pas');
        expect(text).toContain('12 des 412 constats ouverts');
        expect(text).toContain('Les 400 autres');
        expect(text).toContain('399');
        expect(text).toContain('à révoquer et à faire tourner');
        expect(text).toContain("il n'y a rien à monter");
    });

    it('stays quiet when the whole backlog closes by a version bump', () => {
        answer([fix({})], { totalOpenIssues: 12 }, {
            openFindings: 12, addressableByUpgrade: 12, beyondUpgrades: 0, gaps: []
        });

        const text = fixture.nativeElement.textContent as string;
        expect(text).not.toContain('Ce que ce plan ne referme pas');
        expect(text).toContain('Les 12 constats ouverts se ferment tous');
    });

    it('names a family it does not know rather than showing a key', () => {
        // A ninth finding type shipped by a server newer than this screen: it must be counted and
        // named for want of better, never rendered as `remediation.gap_ninth`.
        answer([fix({})], { totalOpenIssues: 5 }, {
            openFindings: 5, addressableByUpgrade: 4, beyondUpgrades: 1,
            gaps: [{ family: 'runtime_drift', findings: 1 }]
        });

        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain("constats d'un autre type");
        expect(text).not.toContain('remediation.gap');
    });

    it('shows no admission when the server did not answer, and keeps the plan', () => {
        answer([fix({})], { totalOpenIssues: 9 });

        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('log4j-core');
        expect(text).not.toContain('Ce que ce plan ne referme pas');
        expect(fixture.componentInstance.error()).toBeNull();
    });

    it('tells "nothing to do" apart from "nothing computable"', () => {
        answer([], { totalOpenIssues: 4 });

        // Four open findings and no plan row: the message must explain that the plan ranks only
        // what a version bump closes, without which the screen looks broken.
        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('Rien à monter de version.');
        expect(text).toContain('4');
    });
});
