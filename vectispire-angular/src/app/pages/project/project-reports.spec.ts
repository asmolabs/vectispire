import { HttpHeaders, provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { SessionStore } from '@/app/core/session.store';
import { missingFromBundles } from '@/app/core/testing/bundles';
import { asSchemaList } from '@/app/core/testing/contract';
import { useEnglish } from '@/app/core/testing/english';
import {
    FAILED_RUN,
    PENDING_RUN,
    PRODUCED_RUN,
    REFUSED_RUN,
    REPORT_ACTIVATION,
    REPORT_PLUGIN,
    UNAPPROVED_PLUGIN,
    reportConflict
} from '@/app/core/testing/report-plugins.fixtures';
import { CONFLICT_KEYS, MANIFEST_STATUS_KEYS, RUN_REASON_KEYS, RUN_STATE_KEYS } from '@/app/shared/report-plugins';
import { POLL_MS, ProjectReports, VERIFY_DOC } from './project-reports';

/**
 * A project's reports, through the DOM.
 *
 * **What is read on screen is what is asserted**: a run's state and reason in words — a refusal never
 * dressed as a failure —, the request button offered to write accounts and auditors and shown disabled,
 * with the reason, to the platform governor; the document saved under the server's own name; a 409 said
 * in the reader's words; the list asked again only while a run can still change.
 */
describe('a project’s reports', () => {
    let fixture: ComponentFixture<ProjectReports>;
    let http: HttpTestingController;
    let saved: { name: string }[];

    const BASE = '/api/v1/projects/12';
    const ANOTHER = { ...REPORT_ACTIVATION, id: 2, pluginId: 'risk-pdf', pluginName: 'Risk PDF' };

    beforeEach(async () => {
        saved = [];
        vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
            saved.push({ name: this.download });
        });
        await TestBed.configureTestingModule({
            imports: [ProjectReports],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();
    });

    afterEach(() => {
        http.verify();
        vi.useRealTimers();
        vi.restoreAllMocks();
    });

    async function open(
        role: string,
        runs: object[] = [PRODUCED_RUN, FAILED_RUN, REFUSED_RUN],
        activations: object[] = [REPORT_ACTIVATION, ANOTHER],
        checked = true
    ): Promise<void> {
        TestBed.inject(SessionStore).open('token', {
            username: 'someone',
            displayName: null,
            role,
            mustChangePassword: false,
            mfaEnabled: false
        });
        useEnglish();
        fixture = TestBed.createComponent(ProjectReports);
        fixture.componentRef.setInput('projectId', 12);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        http.expectOne({ method: 'GET', url: `${BASE}/report-plugins` }).flush(
            asSchemaList('ReportPluginActivationView', activations)
        );
        http.expectOne({ method: 'GET', url: `${BASE}/reports` }).flush(
            checked ? asSchemaList('ReportRunView', runs) : runs
        );
        fixture.detectChanges();
        await fixture.whenStable();
    }

    const dom = () => fixture.nativeElement as HTMLElement;
    const text = (selector: string, root: ParentNode = dom()) =>
        root.querySelector(selector)?.textContent?.replace(/\s+/g, ' ').trim() ?? '';
    const button = (selector: string) =>
        dom().querySelector<HTMLButtonElement>(`${selector} button, button${selector}`);
    const row = (id: number) => dom().querySelector(`[data-testid="run-${id}"]`) as HTMLElement;

    it('words every state and reason, and never dresses a refusal as a failure', async () => {
        await open('USER');

        expect(text('[data-testid="run-state"]', row(34))).toBe('Produced');
        expect(text('[data-testid="run-state"]', row(33))).toBe('Failed');
        expect(text('[data-testid="run-reason"]', row(33))).toBe('The plugin ended with exit code 1.');
        expect(text('[data-testid="run-detail"]', row(33))).toBe('the export has no issues part');
        expect(text('[data-testid="run-state"]', row(32))).toBe('Refused');
        expect(text('[data-testid="run-reason"]', row(32))).toContain('not the declared signer');
        // Two different severities: a refusal is how a tampered plugin shows itself.
        const severity = (id: number) => row(id).querySelector('[data-testid="run-state"]')?.getAttribute('data-p');
        expect(severity(33)).toBe('warn');
        expect(severity(32)).toBe('danger');
        expect(severity(34)).toBe('success');
        // A document only for the produced run.
        expect(row(34).querySelector('[data-testid="download-34"]')).not.toBeNull();
        expect(row(33).querySelector('[data-testid="download-33"]')).toBeNull();
        expect(text('[data-testid="run-provenance"]', row(34))).toContain(PRODUCED_RUN.packageSha256!);
    });

    it('shows a reason this client does not know as sent, never as a key', async () => {
        // Newer than the document this client was built from, so not held to it.
        await open('USER', [{ ...FAILED_RUN, reason: 'brand_new_reason' }], [REPORT_ACTIVATION], false);
        expect(text('[data-testid="run-reason"]', row(33))).toBe('brand_new_reason');
    });

    it('holds every state, reason, status and conflict to a sentence in both bundles', () => {
        expect(
            missingFromBundles([
                ...Object.values(RUN_STATE_KEYS),
                ...Object.values(RUN_REASON_KEYS),
                ...Object.values(MANIFEST_STATUS_KEYS),
                ...Object.values(CONFLICT_KEYS)
            ])
        ).toEqual([]);
        http = TestBed.inject(HttpTestingController);
    });

    it('offers a write account the request and the export, and no activation control', async () => {
        await open('USER');

        expect(button('[data-testid="request-quarterly-summary"]')!.disabled).toBe(false);
        expect(button('#download-project-export')!.disabled).toBe(false);
        expect(dom().querySelector('[data-testid="request-not-allowed"]')).toBeNull();
        expect(dom().querySelector('[data-testid="deactivate-quarterly-summary"]')).toBeNull();
        expect(dom().querySelector('#report-plugin-to-activate')).toBeNull();
        // Not a security lead: the registry, governance reading, is not asked.
        http.expectNone('/api/v1/report-plugins');
    });

    it('shows the platform governor the request and the export disabled, with the reason', async () => {
        await open('SUPERUSER');
        // The governor is a security lead: switching plugins on is offered, from the approved ones only.
        http.expectOne('/api/v1/report-plugins').flush(
            asSchemaList('ReportPluginView', [REPORT_PLUGIN, UNAPPROVED_PLUGIN])
        );
        fixture.detectChanges();

        expect(button('[data-testid="request-quarterly-summary"]')!.disabled).toBe(true);
        expect(button('#download-project-export')!.disabled).toBe(true);
        expect(text('[data-testid="request-not-allowed"]')).toContain('The platform governor acts on nothing');
        expect(text('[data-testid="export-not-allowed"]')).toContain('The platform governor acts on nothing');
        // quarterly-summary is on already and draft-pdf has no approved digest: nothing left to offer.
        expect(fixture.componentInstance.activatable()).toEqual([]);
    });

    it('lets an auditor request a report, then asks again only while a run can still change', async () => {
        vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });
        await open('AUDITOR', [PRODUCED_RUN]);

        button('[data-testid="request-quarterly-summary"]')!.click();
        const request = http.expectOne({ method: 'POST', url: `${BASE}/reports` });
        expect(request.request.body).toEqual({ pluginId: 'quarterly-summary' });
        request.flush(PENDING_RUN, { status: 202, statusText: 'Accepted' });
        fixture.detectChanges();

        expect(text('[data-testid="run-state"]', row(35))).toBe('Waiting');
        expect(text('[data-testid="reports-notice"]')).toContain('it is waiting for the executor');
        // One run of a plugin at a time: the button waits with it, and says why.
        expect(button('[data-testid="request-quarterly-summary"]')!.disabled).toBe(true);
        expect(text('[data-testid="request-in-progress"]')).toContain('One report of a plugin at a time');
        expect(button('[data-testid="request-risk-pdf"]')!.disabled).toBe(false);

        vi.advanceTimersByTime(POLL_MS);
        http.expectOne({ method: 'GET', url: `${BASE}/reports` }).flush([{ ...PRODUCED_RUN, id: 35 }, PRODUCED_RUN]);
        fixture.detectChanges();
        expect(text('[data-testid="run-state"]', row(35))).toBe('Produced');

        // Nothing moving any more: no further request.
        vi.advanceTimersByTime(POLL_MS * 3);
        http.expectNone(`${BASE}/reports`);
    });

    for (const [token, words] of [
        ['report-executor-unavailable', 'its built-in worker is switched off'],
        ['report-plugin-disabled', 'has disabled this plugin'],
        ['report-plugin-not-approved', 'has no approved manifest'],
        ['report-run-in-progress', 'already waiting or running']
    ] as const) {
        it(`says a ${token} refusal in words`, async () => {
            await open('USER');
            button('[data-testid="request-quarterly-summary"]')!.click();
            http.expectOne({ method: 'POST', url: `${BASE}/reports` }).flush(reportConflict(token), {
                status: 409,
                statusText: 'Conflict'
            });
            if (token === 'report-run-in-progress') {
                // The run the page did not know of is fetched, so the reader sees what to wait for.
                http.expectOne({ method: 'GET', url: `${BASE}/reports` }).flush([PENDING_RUN]);
            }
            fixture.detectChanges();
            expect(text('[data-testid="reports-error"]')).toContain(words);
        });
    }

    it('says a plugin switched off since the page loaded is no longer on, not that the project is lost', async () => {
        await open('USER');
        button('[data-testid="request-risk-pdf"]')!.click();
        http.expectOne({ method: 'POST', url: `${BASE}/reports` }).flush(
            { detail: 'Report plugin not switched on.' },
            { status: 404, statusText: 'Not Found' }
        );
        fixture.detectChanges();
        expect(text('[data-testid="reports-error"]')).toBe('Risk PDF is no longer switched on for this project.');
    });

    it('saves a produced run’s package under the name the server gives it', async () => {
        await open('AUDITOR');
        button('[data-testid="download-34"]')!.click();
        const request = http.expectOne({ method: 'GET', url: `${BASE}/reports/34/document` });
        expect(request.request.responseType).toBe('blob');
        request.flush(new Blob(['PK']), {
            headers: new HttpHeaders({
                'Content-Disposition': 'attachment; filename="report-34-quarterly-summary.zip"'
            })
        });

        expect(saved).toEqual([{ name: 'report-34-quarterly-summary.zip' }]);
    });

    describe('a withdrawn manifest’s document', () => {
        const WITHDRAWN = {
            ...PRODUCED_RUN,
            id: 36,
            withdrawnAt: '2026-10-03T14:02:10Z',
            withdrawnBy: 'governor',
            withdrawalJustification: 'The renderer dropped accepted issues from the sheet.'
        };

        const downloadAnswered = (id: number, status: 'upheld' | 'withdrawn') => {
            button(`[data-testid="download-${id}"]`)!.click();
            http.expectOne({ method: 'GET', url: `${BASE}/reports/${id}/document` }).flush(new Blob(['PK']), {
                headers: new HttpHeaders({
                    'Content-Disposition': `attachment; filename="report-${id}-quarterly-summary.zip"`,
                    'Vectispire-Document-Status': status
                })
            });
            fixture.detectChanges();
        };

        it('is marked withdrawn on its row, with the date, who withdrew it and why, and stays downloadable', async () => {
            await open('USER', [WITHDRAWN, PRODUCED_RUN]);

            const mark = row(36).querySelector('[data-testid="run-withdrawn"]');
            expect(mark).not.toBeNull();
            expect(text('p-tag', mark!)).toBe('Withdrawn');
            expect(mark!.textContent).toContain('03/10/2026');
            expect(mark!.textContent).toContain('by governor');
            expect(mark!.textContent).toContain('The renderer dropped accepted issues from the sheet.');
            expect(button('[data-testid="download-36"]')).not.toBeNull();
            expect(row(34).querySelector('[data-testid="run-withdrawn"]')).toBeNull();
        });

        it('says after the download what the document is worth, and nothing for one that stands', async () => {
            await open('USER', [WITHDRAWN, PRODUCED_RUN]);

            downloadAnswered(34, 'upheld');
            expect(dom().querySelector('[data-testid="download-withdrawn"]')).toBeNull();

            downloadAnswered(36, 'withdrawn');
            expect(saved.map((one) => one.name)).toEqual([
                'report-34-quarterly-summary.zip',
                'report-36-quarterly-summary.zip'
            ]);
            const notice = text('[data-testid="download-withdrawn"]');
            expect(notice).toContain('no longer stands by it');
            expect(notice).toContain('The renderer dropped accepted issues from the sheet.');
        });

        it('believes the server over a row read before the withdrawal, and reads the runs again', async () => {
            await open('USER', [PRODUCED_RUN]);

            downloadAnswered(34, 'withdrawn');
            expect(text('[data-testid="download-withdrawn"]')).toBe(
                'This document was withdrawn: its signature still verifies, but the installation no longer stands by it.'
            );
            http.expectOne({ method: 'GET', url: `${BASE}/reports` }).flush(
                asSchemaList('ReportRunView', [{ ...WITHDRAWN, id: 34 }])
            );
            fixture.detectChanges();
            expect(row(34).querySelector('[data-testid="run-withdrawn"]')).not.toBeNull();
        });
    });

    it('says a purged document is gone, rather than that the download failed', async () => {
        await open('USER');
        button('[data-testid="download-34"]')!.click();
        http.expectOne(`${BASE}/reports/34/document`).flush(new Blob(['']), { status: 404, statusText: 'Not Found' });
        fixture.detectChanges();
        expect(text('[data-testid="reports-error"]')).toContain('the evidence window has purged it');
        expect(saved).toEqual([]);
    });

    it('downloads the plain export, and words a project too large to export', async () => {
        await open('USER');
        button('#download-project-export')!.click();
        http.expectOne({ method: 'GET', url: `${BASE}/export` }).flush(new Blob(['PK']), {
            headers: new HttpHeaders({ 'Content-Disposition': 'attachment; filename="gateway-export.zip"' })
        });
        expect(saved).toEqual([{ name: 'gateway-export.zip' }]);

        button('#download-project-export')!.click();
        http.expectOne(`${BASE}/export`).flush(new Blob(['{}']), { status: 409, statusText: 'Conflict' });
        fixture.detectChanges();
        expect(text('[data-testid="reports-error"]')).toContain('refused rather than cut short');
    });

    it('lets a CISO switch an approved plugin on with a PUT and off with a DELETE', async () => {
        await open('CISO', [], [ANOTHER]);
        http.expectOne('/api/v1/report-plugins').flush(
            asSchemaList('ReportPluginView', [REPORT_PLUGIN, UNAPPROVED_PLUGIN])
        );
        fixture.detectChanges();

        // Approved and not on yet: offered. Without an approved digest: not, the server would refuse it.
        expect(fixture.componentInstance.activatable().map((one) => one.value)).toEqual(['quarterly-summary']);
        fixture.componentInstance.toActivate.set('quarterly-summary');
        fixture.detectChanges();
        button('[data-testid="activate"]')!.click();
        http.expectOne({ method: 'PUT', url: `${BASE}/report-plugins/quarterly-summary` }).flush(REPORT_ACTIVATION);
        fixture.detectChanges();
        expect(dom().querySelector('[data-testid="activation-quarterly-summary"]')).not.toBeNull();

        button('[data-testid="deactivate-risk-pdf"]')!.click();
        http.expectOne({ method: 'DELETE', url: `${BASE}/report-plugins/risk-pdf` }).flush(null, {
            status: 204,
            statusText: 'No Content'
        });
        fixture.detectChanges();
        expect(dom().querySelector('[data-testid="activation-risk-pdf"]')).toBeNull();
        expect(text('[data-testid="reports-notice"]')).toBe('Risk PDF is switched off for this project.');
    });

    it('explains the package and links the commands that verify it, in the reader’s language', async () => {
        await open('USER', [], []);
        expect(text('[data-testid="no-runs"]')).toBe('No report requested yet.');
        expect(text('[data-testid="no-activations"]')).toContain('No report plugin is switched on');
        expect(text('[data-testid="package-explained"]')).toContain('provenance.json');
        const link = dom().querySelector('[data-testid="verify-doc"]') as HTMLAnchorElement;
        expect(link.getAttribute('href')).toBe(VERIFY_DOC.en);
        expect(link.getAttribute('rel')).toContain('noopener');

        TestBed.inject(I18nService).currentLang.set('fr');
        fixture.detectChanges();
        expect(link.getAttribute('href')).toBe(VERIFY_DOC.fr);
    });
});
