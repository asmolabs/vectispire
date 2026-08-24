import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { GatePolicies } from './gate-policies';

/**
 * The screen that decides what fails a build.
 *
 * The rules it writes were readable by the gate from the first release and writable by nothing,
 * so every install ran on the built-in default. What this suite is about is the pair of
 * distinctions that make the form dangerous if it gets them wrong:
 *
 * - **"no threshold" is not "unknown".** `fail_on_severity: null` means the severity rule is
 *   off — block on actively exploited findings alone. Sent as an empty string, or read back as
 *   a severity, it becomes a gate that fails everything.
 * - **inheriting is not the same as agreeing.** A target with no policy of its own follows the
 *   global one and keeps following it when it changes; a target whose override happens to hold
 *   the same values does not. The screen has to show which of the two somebody is looking at.
 */
describe('the gate policy screen', () => {
    let fixture: ComponentFixture<GatePolicies>;
    let http: HttpTestingController;

    const BUILT_IN = {
        kind: 'built_in',
        target_id: null,
        target_name: null,
        version: 0,
        fail_on_severity: 'high',
        fail_on_kev: true,
        fixable_only: false,
        include_triaged: false,
        include_ai_review: false,
        note: null,
        created_by: null,
        created_at: null
    };

    const GLOBAL = {
        ...BUILT_IN,
        kind: 'global',
        version: 3,
        fail_on_severity: 'medium',
        note: 'Tightened for the audit.',
        created_by: 'admin',
        created_at: '2026-08-20T09:00:00Z'
    };

    const OVERRIDE = {
        ...BUILT_IN,
        kind: 'repository',
        target_id: 5,
        target_name: 'Arm Libs Spring',
        version: 1,
        fail_on_severity: null,
        note: 'Actively exploited only.',
        created_by: 'admin',
        created_at: '2026-08-21T09:00:00Z'
    };

    function load(policies: unknown[]): void {
        http.expectOne('/api/v1/gate/policies').flush({ policies, built_in: BUILT_IN });
        fixture.detectChanges();
    }

    beforeEach(async () => {
        await TestBed.configureTestingModule({
            imports: [GatePolicies],
            providers: [provideHttpClient(), provideHttpClientTesting()]
        }).compileComponents();

        fixture = TestBed.createComponent(GatePolicies);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
    });

    it('says so when nothing is stored, rather than showing an empty table', () => {
        load([]);

        // An empty table under a heading reads as "no rules apply". The built-in policy always
        // applies, and that is exactly what somebody arriving here needs to be told.
        expect(fixture.nativeElement.textContent).toContain('built-in');
        expect(fixture.componentInstance.globalPolicy()).toBeNull();
    });

    it('separates the global policy from the overrides', () => {
        load([GLOBAL, OVERRIDE]);

        expect(fixture.componentInstance.globalPolicy()?.version).toBe(3);
        expect(fixture.componentInstance.overrides().length).toBe(1);
        expect(fixture.componentInstance.overrides()[0].target_name).toBe('Arm Libs Spring');
    });

    it('shows a null threshold as a rule that is off, not as an unknown severity', () => {
        load([OVERRIDE]);

        // The word matters: "unknown" is a severity the scanners emit, and reading it here as
        // one would describe the strictest possible gate as the loosest.
        expect(fixture.componentInstance.describeThreshold(OVERRIDE.fail_on_severity)).toContain('No severity');
        expect(fixture.componentInstance.describeThreshold('high')).toContain('high');
    });

    it('sends "none" for a rule switched off, and every field on every save', () => {
        load([]);

        fixture.componentInstance.editGlobal();
        fixture.componentInstance.draft.failOnSeverity = 'none';
        fixture.componentInstance.draft.failOnKev = true;
        fixture.componentInstance.save();

        const request = http.expectOne({ method: 'PUT', url: '/api/v1/gate/policies/global' });
        expect(request.request.body.fail_on_severity).toBe('none');
        // Five flags, always: the server refuses a partial policy rather than defaulting the
        // missing half, and a form that omitted one would only find out in production.
        expect(request.request.body.fail_on_kev).toBe(true);
        expect(request.request.body.fixable_only).toBe(false);
        expect(request.request.body.include_triaged).toBe(false);
        expect(request.request.body.include_ai_review).toBe(false);
        request.flush({ ...GLOBAL, version: 1 });
    });

    it('reloads after a save, so the version on screen is the stored one', () => {
        load([]);

        fixture.componentInstance.editGlobal();
        fixture.componentInstance.save();
        http.expectOne({ method: 'PUT', url: '/api/v1/gate/policies/global' }).flush({ ...GLOBAL, version: 1 });

        // Not patched locally: the version number is assigned by the server, and a screen that
        // invented one would be showing a rule nobody can find in the audit log.
        http.expectOne('/api/v1/gate/policies').flush({ policies: [{ ...GLOBAL, version: 1 }], built_in: BUILT_IN });
        fixture.detectChanges();
        expect(fixture.componentInstance.globalPolicy()?.version).toBe(1);
    });

    it('removes an override and reloads, so the target visibly inherits again', () => {
        load([GLOBAL, OVERRIDE]);

        fixture.componentInstance.remove(OVERRIDE as never);
        http.expectOne({ method: 'DELETE', url: '/api/v1/gate/policies/repository/5' }).flush(null);
        http.expectOne('/api/v1/gate/policies').flush({ policies: [GLOBAL], built_in: BUILT_IN });
        fixture.detectChanges();

        expect(fixture.componentInstance.overrides().length).toBe(0);
    });

    it('keeps the server refusal on screen instead of a generic failure', () => {
        load([]);

        fixture.componentInstance.editGlobal();
        fixture.componentInstance.draft.failOnSeverity = 'hgh';
        fixture.componentInstance.save();
        http.expectOne({ method: 'PUT', url: '/api/v1/gate/policies/global' }).flush(
            { detail: 'Unknown severity: "hgh".' },
            { status: 400, statusText: 'Bad Request' }
        );
        fixture.detectChanges();

        // The server is the authority on what a policy may say; repeating its sentence is what
        // lets somebody fix the typo instead of guessing which field it disliked.
        expect(fixture.componentInstance.error()).toContain('hgh');
        expect(fixture.nativeElement.textContent).toContain('hgh');
    });
});
