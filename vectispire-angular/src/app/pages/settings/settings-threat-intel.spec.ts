import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { asSchema } from '@/app/core/testing/contract';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { SettingsState } from './settings-state';
import { SettingsThreatIntel } from './settings-threat-intel';

/**
 * The threat feeds' card: the KEV catalogue, and FIRST's EPSS file beneath it.
 *
 * <p>The feed used to be ten records typed into the control plane, and this card fell back to a
 * green "SYNCED" whenever it had nothing to show. What it has to say now is when the catalogue was
 * last read, how old that catalogue is, and — above all — when the last attempt failed, because the
 * exploitation flags the gate reads are then older than the tiles suggest.
 */
describe('the threat feeds card', () => {
    let fixture: ComponentFixture<SettingsThreatIntel>;
    let http: HttpTestingController;

    const synced = {
        lastSyncedAt: '2026-09-27T06:00:00Z',
        totalCves: 1480,
        totalKev: 1478,
        status: 'SYNCED',
        backlogUpdatedCount: 0,
        kevCatalogVersion: '2026.09.26',
        kevReleasedAt: '2026-09-26T15:00:00Z',
        lastAttemptAt: '2026-09-27T06:00:00Z',
        lastError: null,
        epss: {
            status: 'SYNCED',
            lastSyncedAt: '2026-09-27T13:05:00Z',
            modelVersion: 'v2025.03.14',
            scoreDate: '2026-09-27T12:00:21Z',
            totalScored: 380066,
            lastAttemptAt: '2026-09-27T13:05:00Z',
            lastError: null,
            backlogUpdatedCount: 0,
            inProgress: false
        }
    };

    const epssNever = {
        status: 'NEVER_SYNCED',
        lastSyncedAt: null,
        modelVersion: null,
        scoreDate: null,
        totalScored: 0,
        lastAttemptAt: null,
        lastError: null,
        backlogUpdatedCount: 0,
        inProgress: false
    };

    beforeEach(async () => {
        await TestBed.configureTestingModule({
            imports: [SettingsThreatIntel],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), SettingsState]
        }).compileComponents();

        TestBed.inject(I18nService).translations.set({
            settings: {
                never: 'Never',
                feed_state_synced: 'Synchronized',
                feed_state_failed: 'Last attempt failed',
                feed_state_never_synced: 'Never synchronized',
                kev_catalogue_release: 'Catalogue in use: version {{version}}, released by CISA on {{released}}.',
                kev_last_attempt_failed: 'The attempt of {{at}} failed: {{reason}}.',
                error_threat_intel_sync: 'The KEV catalogue could not be read.',
                threat_intel_synced: 'Catalogue: {{kev}} KEV.',
                epss_cve_count: '{{count}} CVEs',
                epss_file_in_use: 'Scores in use: model {{model}}, scores of {{date}}.',
                epss_last_attempt_failed: 'The EPSS attempt of {{at}} failed: {{reason}}.',
                epss_in_progress: 'An EPSS synchronisation is in progress.',
                epss_synced: 'EPSS: {{count}} CVEs, {{issues}} re-scored.',
                error_epss_sync: 'The EPSS file could not be read.'
            }
        });

        fixture = TestBed.createComponent(SettingsThreatIntel);
        fixture.componentRef.setInput('active', true);
        http = TestBed.inject(HttpTestingController);
    });

    function loaded(status: Record<string, unknown>): HTMLElement {
        fixture.detectChanges();
        http.expectOne('/api/v1/threat-intel/status').flush(asSchema('ThreatIntelSyncStatus', status));
        fixture.detectChanges();
        return fixture.nativeElement as HTMLElement;
    }

    function text(page: HTMLElement, id: string): string {
        return page.querySelector(`[data-testid="${id}"]`)?.textContent?.trim() ?? '';
    }

    it('says when the catalogue was last read, and which catalogue that was', () => {
        const page = loaded(synced);

        expect(text(page, 'feed-state')).toBe('Synchronized');
        expect(text(page, 'kev-synced-at')).toContain('27/09/2026');
        expect(text(page, 'kev-catalogue')).toContain('version 2026.09.26');
        expect(text(page, 'kev-catalogue')).toContain('26/09/2026');
        expect(page.querySelector('[data-testid="kev-failure"]')).toBeNull();
    });

    it('never read is said as such, not as synchronised', () => {
        const page = loaded({
            ...synced,
            status: 'NEVER_SYNCED',
            lastSyncedAt: null,
            totalKev: 0,
            kevCatalogVersion: null,
            kevReleasedAt: null,
            lastAttemptAt: null
        });

        expect(text(page, 'feed-state')).toBe('Never synchronized');
        expect(text(page, 'kev-synced-at')).toBe('Never');
        expect(page.querySelector('[data-testid="kev-catalogue"]')).toBeNull();
    });

    it('a failed attempt is shown with its reason, beside the catalogue still in use', () => {
        const page = loaded({
            ...synced,
            status: 'FAILED',
            lastAttemptAt: '2026-09-27T12:00:00Z',
            lastError: 'KEV catalogue: connection refused'
        });

        expect(text(page, 'feed-state')).toBe('Last attempt failed');
        expect(text(page, 'kev-failure')).toContain('connection refused');
        // The catalogue in use is still named: the flags come from it, and its age is the question.
        expect(text(page, 'kev-catalogue')).toContain('version 2026.09.26');
    });

    it('a sync that answers with a failure is reported as one', () => {
        loaded(synced);

        fixture.componentInstance.syncThreatIntel();
        http.expectOne({ method: 'POST', url: '/api/v1/threat-intel/sync' }).flush(
            asSchema('ThreatIntelSyncStatus', { ...synced, status: 'FAILED', lastError: 'unreachable' })
        );
        fixture.detectChanges();

        // The catalogue's failure is said; the EPSS file, read in the same request, says its own outcome.
        expect(fixture.componentInstance.threatIntelFeedback()).toBe(
            'The KEV catalogue could not be read. EPSS: 380066 CVEs, 0 re-scored.'
        );
    });

    it('says which EPSS file is in use, how old its scores are, and how many CVE it scores', () => {
        const page = loaded(synced);

        expect(text(page, 'epss-state')).toBe('Synchronized');
        expect(text(page, 'epss-count')).toBe('380066 CVEs');
        expect(text(page, 'epss-synced-at')).toContain('27/09/2026');
        expect(text(page, 'epss-file')).toBe('Scores in use: model v2025.03.14, scores of 27/09/2026.');
        expect(page.querySelector('[data-testid="epss-failure"]')).toBeNull();
    });

    it('an EPSS file never read is said as such, and no score date is invented', () => {
        const page = loaded({ ...synced, epss: epssNever });

        expect(text(page, 'epss-state')).toBe('Never synchronized');
        expect(text(page, 'epss-synced-at')).toBe('Never');
        expect(page.querySelector('[data-testid="epss-file"]')).toBeNull();
    });

    it('an EPSS failure is shown with its reason beside the file still in use, whatever the catalogue did', () => {
        const page = loaded({
            ...synced,
            epss: { ...synced.epss, status: 'FAILED', lastError: 'the file is not a whole gzip archive' }
        });

        expect(text(page, 'feed-state')).toBe('Synchronized');
        expect(text(page, 'epss-state')).toBe('Last attempt failed');
        expect(text(page, 'epss-failure')).toContain('not a whole gzip archive');
        expect(text(page, 'epss-file')).toContain('model v2025.03.14');
    });

    it('a sync reports the outcome of each feed, and a request made during another is said to be one', () => {
        loaded(synced);

        fixture.componentInstance.syncThreatIntel();
        http.expectOne({ method: 'POST', url: '/api/v1/threat-intel/sync' }).flush(
            asSchema('ThreatIntelSyncStatus', { ...synced, epss: { ...synced.epss, backlogUpdatedCount: 12 } })
        );
        expect(fixture.componentInstance.threatIntelFeedback()).toBe(
            'Catalogue: 1478 KEV. EPSS: 380066 CVEs, 12 re-scored.'
        );

        fixture.componentInstance.syncThreatIntel();
        http.expectOne({ method: 'POST', url: '/api/v1/threat-intel/sync' }).flush(
            asSchema('ThreatIntelSyncStatus', { ...synced, epss: { ...synced.epss, status: 'FAILED', lastError: 'x' } })
        );
        expect(fixture.componentInstance.threatIntelFeedback()).toBe(
            'Catalogue: 1478 KEV. The EPSS file could not be read.'
        );

        fixture.componentInstance.syncThreatIntel();
        http.expectOne({ method: 'POST', url: '/api/v1/threat-intel/sync' }).flush(
            asSchema('ThreatIntelSyncStatus', { ...synced, epss: { ...synced.epss, inProgress: true } })
        );
        expect(fixture.componentInstance.threatIntelFeedback()).toBe(
            'Catalogue: 1478 KEV. An EPSS synchronisation is in progress.'
        );
    });
});
