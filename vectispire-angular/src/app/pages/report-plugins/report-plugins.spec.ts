import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { afterEach, describe, expect, it } from 'vitest';
import { SessionStore } from '@/app/core/session.store';
import { asSchemaList } from '@/app/core/testing/contract';
import { useEnglish } from '@/app/core/testing/english';
import {
    APPROVED_DIGEST,
    PENDING_DIGEST,
    PENDING_MANIFEST,
    REPORT_MANIFEST,
    REPORT_PLUGIN,
    reportConflict
} from '@/app/core/testing/report-plugins.fixtures';
import { ReportPlugins } from './report-plugins';

/**
 * The report plugin registry, through the DOM.
 *
 * **Who sees which gesture is the whole point.** The governor registers, enables and withdraws; a security
 * lead approves — and never the digest they registered themselves, whatever four-eyes says now, which the
 * page says beside a disabled button instead of letting the click meet a 409. An auditor reads it all and changes
 * nothing. Every case signs in as one of them and reads what the page offers.
 */
describe('the report plugin registry', () => {
    let fixture: ComponentFixture<ReportPlugins>;
    let http: HttpTestingController;

    async function start(role: string, username: string, plugins = [REPORT_PLUGIN]): Promise<void> {
        await TestBed.configureTestingModule({
            imports: [ReportPlugins],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();
        TestBed.inject(SessionStore).open('token', {
            username,
            displayName: null,
            role,
            mustChangePassword: false,
            mfaEnabled: false
        });
        useEnglish();
        fixture = TestBed.createComponent(ReportPlugins);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        http.expectOne({ method: 'GET', url: '/api/v1/report-plugins' }).flush(
            asSchemaList('ReportPluginView', plugins)
        );
        fixture.detectChanges();
    }

    afterEach(() => http.verify());

    const dom = () => fixture.nativeElement as HTMLElement;
    const text = (root: ParentNode, selector: string) =>
        root.querySelector(selector)?.textContent?.replace(/\s+/g, ' ').trim() ?? '';
    const button = (root: ParentNode, selector: string) =>
        root.querySelector<HTMLButtonElement>(`${selector} button, button${selector}`);
    const manifest = (digest: string) => dom().querySelector(`[data-testid="manifest-${digest}"]`) as HTMLElement;

    function open(id = 'quarterly-summary'): void {
        button(dom(), `[data-testid="open-${id}"]`)!.click();
        fixture.detectChanges();
    }

    function type(selector: string, value: string): void {
        const field = document.querySelector(selector) as HTMLTextAreaElement;
        field.value = value;
        field.dispatchEvent(new Event('input'));
        fixture.detectChanges();
    }

    it('shows an auditor the plugins, their approved and pending digests, and offers no change', async () => {
        await start('AUDITOR', 'auditor');

        const row = text(dom(), '[data-testid="report-plugin-quarterly-summary"]');
        expect(row).toContain('Quarterly risk summary');
        expect(text(dom(), '[data-testid="approved-digest"]')).toBe(APPROVED_DIGEST.slice(0, 12));
        expect(text(dom(), '[data-testid="pending-digest"]')).toContain(PENDING_DIGEST.slice(0, 12));
        expect(dom().querySelector('#register-report-plugin')).toBeNull();
        expect(dom().querySelector('[data-testid="enable-quarterly-summary"]')).toBeNull();
        // Why a digest waits, said to everybody who reads the registry.
        expect(text(dom(), '[data-testid="four-eyes-explained"]')).toContain('somebody other than the account');

        open();
        expect(text(manifest(PENDING_DIGEST), '[data-testid="manifest-status"]')).toBe('Awaiting approval');
        expect(text(manifest(APPROVED_DIGEST), '[data-testid="manifest-status"]')).toBe('Approved');
        expect(text(manifest(APPROVED_DIGEST), '[data-testid="manifest-approved"]')).toContain(
            'by a second person (four-eyes)'
        );
        expect(dom().querySelector('[data-testid="approve"]')).toBeNull();
        expect(dom().querySelector('[data-testid="withdraw"]')).toBeNull();
    });

    it('lets a CISO approve a digest somebody else registered, with a POST on that digest', async () => {
        await start('CISO', 'ciso');
        open();

        const approve = button(manifest(PENDING_DIGEST), '[data-testid="approve"]')!;
        expect(approve.disabled).toBe(false);
        expect(manifest(PENDING_DIGEST).querySelector('[data-testid="approve-four-eyes"]')).toBeNull();
        // Approving is for a digest waiting; the approved one offers no second approval.
        expect(manifest(APPROVED_DIGEST).querySelector('[data-testid="approve"]')).toBeNull();
        // Withdrawing is the governor's, not a CISO's.
        expect(dom().querySelector('[data-testid="withdraw"]')).toBeNull();

        approve.click();
        http.expectOne({
            method: 'POST',
            url: `/api/v1/report-plugins/quarterly-summary/manifests/${PENDING_DIGEST}/approval`
        }).flush({
            ...REPORT_PLUGIN,
            approvedDigest: PENDING_DIGEST,
            pendingDigest: null,
            manifests: [
                { ...PENDING_MANIFEST, status: 'approved', approvedBy: 'ciso', approvedAt: '2026-10-03T09:00:00Z' }
            ]
        });
        fixture.detectChanges();

        expect(text(dom(), '[data-testid="registry-notice"]')).toContain(
            `digest ${PENDING_DIGEST.slice(0, 12)} approved`
        );
        expect(text(dom(), '[data-testid="pending-digest"]')).toBe('—');
    });

    it('keeps the registrant from approving their own digest whatever four-eyes says now, and says why', async () => {
        await start('SUPERUSER', 'governor');
        open();

        // Only a registration made under four-eyes waits, and it is approved under the rule it was registered
        // under: turning four-eyes off since frees nothing, so the page does not read the setting at all
        // (`http.verify()` after each case fails on a settings request nobody answered).
        const approve = button(manifest(PENDING_DIGEST), '[data-testid="approve"]')!;
        expect(approve.disabled).toBe(true);
        expect(text(manifest(PENDING_DIGEST), '[data-testid="approve-four-eyes"]')).toContain(
            'You registered this digest'
        );
    });

    it('words a four-eyes refusal from the server in the reader’s language, not the server’s sentence', async () => {
        await start('ADMIN', 'admin');
        open();

        button(manifest(PENDING_DIGEST), '[data-testid="approve"]')!.click();
        http.expectOne(`/api/v1/report-plugins/quarterly-summary/manifests/${PENDING_DIGEST}/approval`).flush(
            reportConflict('report-plugin-four-eyes', 'Four-eyes approval: manifest … registered by admin.'),
            { status: 409, statusText: 'Conflict' }
        );
        fixture.detectChanges();

        expect(text(dom(), '[data-testid="registry-error"]')).toContain(
            'the account that registered a digest cannot approve it'
        );
    });

    it('says every problem of a pasted manifest in words, and sends it only once it reads correctly', async () => {
        await start('SUPERUSER', 'governor');

        button(dom(), '#register-report-plugin')!.click();
        fixture.detectChanges();
        const save = () => button(document, '[data-testid="save-manifest"]')!;

        type('#report-manifest', '{ not json');
        expect(text(document, '[data-testid="manifest-problems"]')).toContain('This is not JSON');
        expect(save().disabled).toBe(true);

        type(
            '#report-manifest',
            JSON.stringify({
                ...REPORT_MANIFEST,
                image: 'registry.example.internal/reports/quarterly-summary:latest',
                output: 'summary.xlsm',
                network: false,
                signature: { identity: 'x' }
            })
        );
        const problems = text(document, '[data-testid="manifest-problems"]');
        expect(problems).toContain('image: pinned by digest');
        expect(problems).toContain('output: ends with .xlsx');
        expect(problems).toContain('signature: required');
        expect(problems).toContain('always runs without a network');
        expect(save().disabled).toBe(true);

        type('#report-manifest', JSON.stringify(REPORT_MANIFEST));
        expect(text(document, '[data-testid="manifest-ok"]')).toContain('reads correctly');
        save().click();
        const request = http.expectOne({ method: 'POST', url: '/api/v1/report-plugins' });
        expect(request.request.body).toEqual(REPORT_MANIFEST);
        request.flush(reportConflict('report-plugin-id-taken'), { status: 409, statusText: 'Conflict' });
        fixture.detectChanges();

        // Kept in the dialog, in words, where the id can still be changed.
        expect(text(document, '[data-testid="manifest-error"]')).toContain('ids are never reused');
    });

    it('gives an existing plugin a new manifest with a PUT, and holds it to the same id', async () => {
        await start('SUPERUSER', 'governor');

        button(dom(), '[aria-label="Give quarterly-summary a new manifest"]')!.click();
        fixture.detectChanges();
        // `ngModel` writes the field in a microtask.
        await fixture.whenStable();
        // The manifest it runs is the starting point.
        expect((document.querySelector('#report-manifest') as HTMLTextAreaElement).value).toContain(
            'quarterly-summary'
        );

        type('#report-manifest', JSON.stringify({ ...REPORT_MANIFEST, id: 'other-id' }));
        expect(text(document, '[data-testid="manifest-problems"]')).toContain(
            "keeps the plugin's id, quarterly-summary"
        );

        type('#report-manifest', JSON.stringify({ ...REPORT_MANIFEST, timeout_seconds: 240 }));
        button(document, '[data-testid="save-manifest"]')!.click();
        const request = http.expectOne({ method: 'PUT', url: '/api/v1/report-plugins/quarterly-summary' });
        expect(request.request.body.timeout_seconds).toBe(240);
        request.flush(REPORT_PLUGIN);
        http.expectOne('/api/v1/report-plugins').flush([REPORT_PLUGIN]);
        fixture.detectChanges();
        expect(text(dom(), '[data-testid="registry-notice"]')).toContain('awaits a second person');
    });

    it('withdraws a digest only with a justification of 20 to 500 characters, sent trimmed', async () => {
        await start('SUPERUSER', 'governor');
        open();

        button(manifest(APPROVED_DIGEST), '[data-testid="withdraw"]')!.click();
        fixture.detectChanges();
        const confirm = () => button(document, '[data-testid="confirm-withdrawal"]')!;

        type('#report-withdrawal-justification', 'too short');
        expect(confirm().disabled).toBe(true);
        expect(text(document, '[data-testid="withdrawal-count"]')).toContain('9 characters');

        type('#report-withdrawal-justification', '  The renderer dropped every low issue.  ');
        expect(confirm().disabled).toBe(false);
        confirm().click();
        const request = http.expectOne({
            method: 'POST',
            url: `/api/v1/report-plugins/quarterly-summary/manifests/${APPROVED_DIGEST}/withdrawal`
        });
        expect(request.request.body).toEqual({ justification: 'The renderer dropped every low issue.' });
        request.flush({
            ...REPORT_PLUGIN,
            approvedDigest: null,
            manifests: [
                PENDING_MANIFEST,
                {
                    ...REPORT_PLUGIN.manifests[1],
                    status: 'withdrawn',
                    withdrawnAt: '2026-10-03T10:00:00Z',
                    withdrawnBy: 'governor',
                    withdrawalJustification: 'The renderer dropped every low issue.'
                }
            ]
        });
        fixture.detectChanges();

        expect(text(manifest(APPROVED_DIGEST), '[data-testid="manifest-status"]')).toBe('Withdrawn');
        expect(text(manifest(APPROVED_DIGEST), '[data-testid="withdrawal-justification"]')).toBe(
            'The renderer dropped every low issue.'
        );
        // Final: a withdrawn digest offers no second withdrawal.
        expect(manifest(APPROVED_DIGEST).querySelector('[data-testid="withdraw"]')).toBeNull();
        expect(text(dom(), '[data-testid="approved-digest"]')).toContain('none — cannot run');
    });

    it('lets the governor disable a plugin with a PUT on /enabled', async () => {
        await start('SUPERUSER', 'governor');

        button(dom(), '[data-testid="enable-quarterly-summary"]')!.click();
        const request = http.expectOne({ method: 'PUT', url: '/api/v1/report-plugins/quarterly-summary/enabled' });
        expect(request.request.body).toEqual({ enabled: false });
        request.flush({ ...REPORT_PLUGIN, enabled: false });
        fixture.detectChanges();

        expect(text(dom(), '[data-testid="report-plugin-quarterly-summary"]')).toContain('Disabled');
        expect(text(dom(), '[data-testid="registry-notice"]')).toContain('its activations are kept');
    });
});
