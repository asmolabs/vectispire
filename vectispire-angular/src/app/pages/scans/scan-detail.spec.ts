import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { ScanDetailPage } from './scan-detail';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { asSchema } from '@/app/core/testing/contract';

/**
 * One scan's detail, against the shape the server actually sends.
 *
 * <p><b>The summary arrives nested under `scan`.</b> The page used to read `detail.id`,
 * `detail.branch`, `detail.status` and the three counters straight off the response, because the
 * client type said `ScanDetail extends ScanSummary` — a claim nobody had checked against the
 * document. Ten fields of the header rendered blank and the page still loaded, so there was
 * nothing to notice. This fixture is the response the routes produce, and it is what makes the
 * omission visible.
 */
describe('the scan detail', () => {
    let fixture: ComponentFixture<ScanDetailPage>;
    let http: HttpTestingController;

    // Read against the document rather than believed: this exact fixture used to spread the
    // summary flat, which is what let the screen's ten blank fields go unnoticed.
    const DETAIL = asSchema('ScanDetail', {
        scan: {
            id: 34,
            status: 'completed',
            branch: 'master',
            createdAt: '2026-08-21T05:03:00Z',
            durationMs: 42_000,
            findingsCount: 3,
            newIssuesCount: 2,
            resolvedIssuesCount: 1,
            error: null,
            claimedBy: 'agent-eu-1',
            attempts: 1,
            targetKind: 'repository',
            targetId: 5,
            targetName: 'Arm Libs Spring'
        },
        subPath: null,
        projectType: 'gradle',
        projectVersion: '1.17.6',
        hasSbom: true,
        findingsTotal: 3,
        findingsTruncated: false,
        findings: [
            {
                id: 1,
                type: 'vulnerability',
                severity: 'high',
                identifier: 'CVE-2026-1234',
                packageName: 'openssl',
                packageVersion: '3.0.1',
                fixVersions: '3.0.14',
                filePath: null,
                line: null,
                description: 'A flaw in the parser.',
                link: null
            }
        ]
    });

    const COVERED = asSchema('Assessment', {
        state: 'COVERED',
        languagesWithRules: ['java'],
        ecosystemsInEstate: ['maven'],
        uncovered: [],
        ruleFiles: 40
    });

    beforeEach(async () => {
        await TestBed.configureTestingModule({
            imports: [ScanDetailPage],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        TestBed.inject(I18nService).translations.set({
            common: { loading: 'Loading…' },
            rule_coverage: {
                import: 'Import a catalogue',
                add: 'Add this language',
                unconfigured: {
                    title: 'Code analysis covers one pattern, in Python.',
                    body: 'Your repositories are not analysed.'
                },
                partial: { title: 'No rule covers', body: 'Injection is not measured there.' }
            }
        });

        fixture = TestBed.createComponent(ScanDetailPage);
        fixture.componentRef.setInput('id', '34');
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
    });

    async function load(
        detail: Record<string, unknown> = DETAIL,
        coverage: Record<string, unknown> = COVERED
    ): Promise<void> {
        // The request is queued on a microtask so the required input is set before it fires.
        await Promise.resolve();
        http.expectOne('/api/v1/scans/34').flush(detail);
        fixture.detectChanges();

        // The coverage banner sits inside the block that waits for the detail, so it asks only
        // once the screen has rendered.
        http.expectOne('/api/v1/rule-sets/coverage').flush(coverage);
        fixture.detectChanges();
    }

    it('names the scan and its target from the nested summary', async () => {
        await load();

        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('34');
        expect(text).toContain('Arm Libs Spring');
        expect(text).toContain('master');
    });

    it('shows the three counters the summary carries', async () => {
        await load();

        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('3');
        expect(text).toContain('2');
        expect(text).toContain('1');
    });

    it('reports a failure from the summary, not from the detail', async () => {
        await load({
            ...DETAIL,
            scan: { ...DETAIL.scan, status: 'failed', error: 'the agent never claimed it' }
        });

        expect(fixture.nativeElement.textContent as string).toContain('the agent never claimed it');
    });

    it('lists the findings of this scan', async () => {
        await load();

        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('CVE-2026-1234');
        expect(text).toContain('openssl');
    });

    /**
     * <b>An empty findings list is the sentence this screen gets wrong on its own.</b> A scan of a
     * repository no rule covers reports nothing, and the table below says "no finding" in the
     * same words it uses for a repository that is genuinely clean. The banner is what separates
     * "nothing was found" from "nothing was looked for", and this is the screen the design note
     * named first.
     */
    it('says an empty findings list may be an empty search', async () => {
        await load({ ...DETAIL, findings: [], findingsTotal: 0 }, {
            state: 'UNCONFIGURED',
            languagesWithRules: [],
            ecosystemsInEstate: ['maven'],
            uncovered: ['maven'],
            ruleFiles: 1
        });

        expect(fixture.nativeElement.textContent as string).toContain(
            'Code analysis covers one pattern, in Python.'
        );
    });

    it('stays quiet when the estate is covered, so the one that matters stays visible', async () => {
        await load();

        expect(fixture.nativeElement.textContent as string).not.toContain('Code analysis covers');
    });
});
