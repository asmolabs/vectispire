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
            notBefore: null,
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
        ],
        plugins: [],
        examinedTypes: ['secret', 'vulnerability']
    });

    /** One plugin in each of its three states, as `PluginOutcome.of` writes them. */
    const PLUGINS = [
        asSchema('PluginOutcome', {
            pluginId: 'acme-lint',
            manifestDigest: 'c'.repeat(64),
            state: 'produced',
            findings: 4,
            languages: [],
            reason: null,
            refusal: null,
            signature: 'verified'
        }),
        asSchema('PluginOutcome', {
            pluginId: 'kotlin-rules',
            manifestDigest: 'd'.repeat(64),
            state: 'not_applicable',
            findings: null,
            languages: ['kotlin'],
            reason: null,
            refusal: null,
            signature: null
        }),
        asSchema('PluginOutcome', {
            pluginId: 'house-secrets',
            manifestDigest: 'e'.repeat(64),
            state: 'absent',
            findings: null,
            languages: [],
            reason: 'exit code 2 is not a declared exit code',
            refusal: null,
            signature: null
        })
    ];

    /** The executor's refusals and a plugin run under the governor's waiver (decision 0017 §9.1). */
    const SIGNATURE_OUTCOMES = [
        asSchema('PluginOutcome', {
            pluginId: 'unsigned-one',
            manifestDigest: 'f'.repeat(64),
            state: 'refused',
            findings: null,
            languages: [],
            reason: 'its manifest declares no signer; it was not run',
            refusal: 'unsigned',
            signature: null
        }),
        asSchema('PluginOutcome', {
            pluginId: 'impostor',
            manifestDigest: 'f'.repeat(64),
            state: 'refused',
            findings: null,
            languages: [],
            reason: 'cosign: no matching signatures',
            refusal: 'signature_unverified',
            signature: null
        }),
        asSchema('PluginOutcome', {
            pluginId: 'waived-one',
            manifestDigest: 'f'.repeat(64),
            state: 'produced',
            findings: 0,
            languages: [],
            reason: null,
            refusal: null,
            signature: 'waived'
        })
    ];

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
            scans: { retry_at: 'Retry at {{ time }}.' },
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

    it('says when a waiting scan whose attempt could not run may be tried again', async () => {
        const later = new Date(Date.now() + 5 * 60_000).toISOString();
        await load({
            ...DETAIL,
            scan: {
                ...DETAIL.scan,
                status: 'pending',
                error: 'Attempt 1 of 3 could not run on agent "edge"; the scan is back in the queue',
                notBefore: later
            }
        });

        const retry = fixture.nativeElement.querySelector('[data-testid="scan-retry-at"]') as HTMLElement | null;
        expect(retry).not.toBeNull();
        expect(retry?.textContent).toContain('Retry at');
    });

    it('says nothing of a retry once its moment has passed, or for a scan that is not waiting', async () => {
        const page = fixture.componentInstance;
        const earlier = new Date(Date.now() - 60_000).toISOString();
        const later = new Date(Date.now() + 60_000).toISOString();

        expect(page.retryAt({ ...DETAIL.scan, status: 'pending', notBefore: earlier })).toBeNull();
        expect(page.retryAt({ ...DETAIL.scan, status: 'failed', notBefore: later })).toBeNull();
        expect(page.retryAt({ ...DETAIL.scan, status: 'pending', notBefore: null })).toBeNull();
        expect(page.retryAt({ ...DETAIL.scan, status: 'pending', notBefore: later })).toBe(later);

        await load();
        expect(fixture.nativeElement.querySelector('[data-testid="scan-retry-at"]')).toBeNull();
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
        await load(
            { ...DETAIL, findings: [], findingsTotal: 0 },
            {
                state: 'UNCONFIGURED',
                languagesWithRules: [],
                ecosystemsInEstate: ['maven'],
                uncovered: ['maven'],
                ruleFiles: 1
            }
        );

        expect(fixture.nativeElement.textContent as string).toContain('Code analysis covers one pattern, in Python.');
    });

    /**
     * **Not applicable is not a failure, absent is** (decision 0017 §4). Rendered alike, every scan
     * of a Python repository would carry a red row for the Java plugin, and the one plugin that did
     * fail would be one red row among many. Each state is read here from the DOM: its own marker,
     * its own tag, its own detail — and the not-applicable row carries nothing of a failure.
     */
    it("renders each plugin's state distinctly, and only absent as a failure", async () => {
        await load({ ...DETAIL, plugins: PLUGINS });

        const rows = Array.from(
            (fixture.nativeElement as HTMLElement).querySelectorAll('[data-testid="plugin-outcome"]')
        );
        expect(rows.map((row) => row.getAttribute('data-state'))).toEqual(['produced', 'not_applicable', 'absent']);

        const [produced, skipped, absent] = rows.map((row) => row.textContent ?? '');
        expect(produced).toContain('scans.plugin_state.produced');
        expect(produced).toContain('scans.plugin_findings');
        expect(skipped).toContain('scans.plugin_state.not_applicable');
        expect(skipped).not.toContain('scans.plugin_state.absent');
        expect(absent).toContain('scans.plugin_state.absent');
        expect(absent).toContain('exit code 2 is not a declared exit code');

        // The tag's colour is the other half of "distinct": only the absent one is danger.
        expect(rows[2].querySelector('.p-tag-danger')).not.toBeNull();
        expect(rows[1].querySelector('.p-tag-danger')).toBeNull();
        expect(rows[0].querySelector('.p-tag-danger')).toBeNull();
    });

    it('names a refusal by its reason, as a failure, and marks a plugin that ran under a waiver', async () => {
        await load({ ...DETAIL, plugins: [...PLUGINS, ...SIGNATURE_OUTCOMES] });

        const rows = Array.from(
            (fixture.nativeElement as HTMLElement).querySelectorAll('[data-testid="plugin-outcome"]')
        );
        const [produced, , , unsigned, impostor, waived] = rows;
        expect(unsigned.getAttribute('data-state')).toBe('refused');
        expect(unsigned.textContent).toContain('scans.plugin_refusal.unsigned');
        expect(unsigned.textContent).toContain('declares no signer');
        expect(unsigned.textContent).not.toContain('scans.plugin_state.absent');
        expect(unsigned.querySelector('.p-tag-danger')).not.toBeNull();
        expect(impostor.textContent).toContain('scans.plugin_refusal.signature_unverified');
        expect(impostor.textContent).toContain('no matching signatures');

        expect(waived.querySelector('[data-testid="plugin-waived"]')?.textContent).toContain('scans.plugin_waived');
        expect(waived.querySelector('.p-tag-danger')).toBeNull();
        expect(produced.querySelector('[data-testid="plugin-waived"]')).toBeNull();
    });

    it("links each plugin to the registry and shows the manifest's digest", async () => {
        await load({ ...DETAIL, plugins: PLUGINS });

        const link = (fixture.nativeElement as HTMLElement).querySelector('[data-testid="plugin-outcome"] a');
        expect(link?.getAttribute('href')).toBe('/plugins?id=acme-lint');
        expect(fixture.nativeElement.textContent as string).toContain('c'.repeat(12));
    });

    it('shows no plugin card for a scan that ran none', async () => {
        await load();

        expect((fixture.nativeElement as HTMLElement).querySelector('[data-testid="scan-plugins"]')).toBeNull();
    });

    it("names the tool that reported a plugin's finding", async () => {
        await load({
            ...DETAIL,
            findings: [
                asSchema('FindingView', {
                    ...DETAIL.findings[0],
                    id: 2,
                    type: 'plugin',
                    identifier: 'acme.no-internal-http',
                    tool: 'plugin:acme-lint',
                    toolName: 'acme-lint',
                    toolVersion: '1.4.0'
                })
            ]
        });

        const tool = (fixture.nativeElement as HTMLElement).querySelector('[data-testid="finding-tool"]');
        expect(tool?.textContent).toContain('scans.reported_by');
        // The type's own label, a literal key: the dynamic `issues.types.${type}` it replaces was
        // invisible to the i18n check.
        expect(fixture.nativeElement.textContent as string).toContain('issues.types.plugin');
    });

    /**
     * **Which built-in steps looked (decision 0032).** A step that produced examined the tree; one
     * left out did not look, and its issues were left as they were. Read from the DOM: each type in
     * its own group, by its wire name.
     */
    it('shows which built-in steps examined the tree, and which did not', async () => {
        await load({ ...DETAIL, examinedTypes: ['secret', 'vulnerability'] });

        const root = fixture.nativeElement as HTMLElement;
        const typesOf = (testId: string) =>
            Array.from(root.querySelectorAll(`[data-testid="${testId}"]`)).map((tag) => tag.getAttribute('data-type'));
        expect(root.querySelector('[data-testid="scan-examined"]')).not.toBeNull();
        expect(typesOf('examined-type')).toEqual(['vulnerability', 'secret']);
        expect(typesOf('not-examined-type')).toEqual(['iac', 'license', 'eol', 'sast', 'quality']);
        // The tool-scoped types are no step of the scan's own: plugins have their card.
        expect(typesOf('not-examined-type')).not.toContain('plugin');
        expect(root.querySelector('[data-testid="scan-examined-unrecorded"]')).toBeNull();
    });

    /**
     * **Null is "not recorded", and the screen says it.** Read as an empty list, a scan from before
     * the upgrade would show every step as not examined — a tree "never searched for secrets" when
     * nothing wrote down whether it was.
     */
    it('says a completed scan from before the upgrade did not record what it examined', async () => {
        await load({ ...DETAIL, examinedTypes: null });

        const root = fixture.nativeElement as HTMLElement;
        expect(root.querySelector('[data-testid="scan-examined-unrecorded"]')?.textContent).toContain(
            'scans.examined_unrecorded'
        );
        expect(root.querySelectorAll('[data-testid="not-examined-type"]')).toHaveLength(0);
        expect(root.querySelectorAll('[data-testid="examined-type"]')).toHaveLength(0);
    });

    it('says a recorded scan in which no step produced examined nothing', async () => {
        await load({ ...DETAIL, scan: { ...DETAIL.scan, status: 'failed' }, examinedTypes: [] });

        const root = fixture.nativeElement as HTMLElement;
        expect(root.querySelector('[data-testid="scan-examined-none"]')).not.toBeNull();
        expect(root.querySelector('[data-testid="scan-examined-unrecorded"]')).toBeNull();
        expect(root.querySelectorAll('[data-testid="not-examined-type"]')).toHaveLength(7);
    });

    it('says nothing of an examination for a scan that has not run yet', async () => {
        await load({ ...DETAIL, scan: { ...DETAIL.scan, status: 'pending' }, examinedTypes: null });

        expect((fixture.nativeElement as HTMLElement).querySelector('[data-testid="scan-examined"]')).toBeNull();
    });

    it('stays quiet when the estate is covered, so the one that matters stays visible', async () => {
        await load();

        expect(fixture.nativeElement.textContent as string).not.toContain('Code analysis covers');
    });

    /**
     * Following a link from one scan to another keeps this component and changes only `id`. The
     * two answers race: the slower first one used to land last and put the previous scan's target
     * and findings under the new scan's address.
     */
    describe('moving from one scan to the next', () => {
        const NEXT = { ...DETAIL, scan: { ...DETAIL.scan, id: 35, targetName: 'Billing Gateway' } };

        async function moveTo(id: string): Promise<void> {
            fixture.componentRef.setInput('id', id);
            fixture.detectChanges();
            await Promise.resolve();
        }

        it("shows the scan the address names when the previous scan's answer comes last", async () => {
            await Promise.resolve();
            const first = http.expectOne('/api/v1/scans/34');

            await moveTo('35');
            http.expectOne('/api/v1/scans/35').flush(NEXT);
            // A request still open would deliver the old answer now; a cancelled one cannot.
            if (!first.cancelled) first.flush(DETAIL);
            fixture.detectChanges();
            for (const coverage of http.match('/api/v1/rule-sets/coverage')) coverage.flush(COVERED);
            fixture.detectChanges();

            expect(first.cancelled).toBe(true);
            const text = (fixture.nativeElement as HTMLElement).textContent;
            expect(text).toContain('Billing Gateway');
            expect(text).not.toContain('Arm Libs Spring');
        });

        it('takes the previous scan off the screen while the next one loads', async () => {
            await load();
            expect((fixture.nativeElement as HTMLElement).textContent).toContain('Arm Libs Spring');

            await moveTo('35');

            expect((fixture.nativeElement as HTMLElement).textContent).not.toContain('Arm Libs Spring');
            http.expectOne('/api/v1/scans/35').flush(NEXT);
        });
    });
});
