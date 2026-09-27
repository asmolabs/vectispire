import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { asSchema } from '@/app/core/testing/contract';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { SettingsState } from './settings-state';
import { SettingsThreatIntel } from './settings-threat-intel';

/**
 * The KEV feed's card.
 *
 * <p>The feed used to be ten records typed into the control plane, and this card fell back to a
 * green "SYNCED" whenever it had nothing to show. What it has to say now is when the catalogue was
 * last read, how old that catalogue is, and — above all — when the last attempt failed, because the
 * exploitation flags the gate reads are then older than the tiles suggest.
 */
describe('the KEV feed card', () => {
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
        lastError: null
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
                error_threat_intel_sync: 'The KEV catalogue could not be read.'
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

        expect(fixture.componentInstance.threatIntelFeedback()).toBe('The KEV catalogue could not be read.');
    });
});
