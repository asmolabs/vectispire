import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { GatePolicies, THRESHOLD_KEYS } from './gate-policies';
import { missingFromBundles } from '@/app/core/testing/bundles';
import { asSchema } from '@/app/core/testing/contract';
import { useEnglish, useFrench } from '@/app/core/testing/english';
import type { GatePolicy, GatePolicyRequest } from '@/app/core/api.models';

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

    // Read against the document: this fixture survived the addition of a field the server now
    // always sends, and the form sent it back as `undefined` without anything saying so.
    const BUILT_IN: GatePolicy = asSchema('GatePolicyView', {
        kind: 'built_in',
        target_id: null,
        target_name: null,
        version: 0,
        fail_on_severity: 'high',
        fail_on_kev: true,
        fixable_only: false,
        include_triaged: false,
        include_ai_review: false,
        fail_on_uncovered_languages: false,
        include_plugins: false,
        note: null,
        created_by: null,
        created_at: null
    });

    const GLOBAL: GatePolicy = {
        ...BUILT_IN,
        kind: 'global',
        version: 3,
        fail_on_severity: 'medium',
        note: 'Tightened for the audit.',
        created_by: 'admin',
        created_at: '2026-08-20T09:00:00Z'
    };

    const OVERRIDE: GatePolicy = {
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
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting()]
        }).compileComponents();

        fixture = TestBed.createComponent(GatePolicies);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
    });

    it('says so when nothing is stored, rather than showing an empty table', () => {
        load([]);

        // An empty table under a heading reads as "no rules apply". The built-in policy always
        // applies, and that is exactly what somebody arriving here needs to be told.
        // The key, not the sentence: this harness renders keys unresolved, and pinning the
        // wording would break on the next rewording while proving nothing more.
        expect((fixture.nativeElement as HTMLElement).textContent).toContain('gate_policies.nothing_stored_strong');
        expect(fixture.componentInstance.globalPolicy()).toBeNull();
    });

    it('dates a policy as every date of the interface reads, not by a locale written in the code', () => {
        // `toLocaleString('fr-BE', …)` wrote "20/08/26 09:00" — a two-digit year no other screen
        // shows. Built from local fields: the pattern writes local time.
        const at = new Date(2026, 7, 20, 9, 0).toISOString();

        expect(fixture.componentInstance.formatDate(at)).toBe('20/08/2026 09:00');
        expect(fixture.componentInstance.formatDate(null)).toBe('—');
    });

    it('separates the global policy from the overrides', () => {
        load([GLOBAL, OVERRIDE]);

        expect(fixture.componentInstance.globalPolicy()?.version).toBe(3);
        expect(fixture.componentInstance.overrides().length).toBe(1);
        expect(fixture.componentInstance.overrides()[0].target_name).toBe('Arm Libs Spring');
    });

    it('shows a null threshold as a rule that is off, not as an unknown severity', () => {
        load([OVERRIDE]);

        // **The key it resolves, not the sentence it used to build.** `describeThreshold` no
        // longer spells the five thresholds out — it looks up `severity_rules.*`, which the
        // select was already using, so the same value can no longer read one way in the dropdown
        // and another in the card. The distinction the test defends is unchanged: `null` must
        // reach the `none` entry and never be shown as a severity the scanners emit.
        expect(fixture.componentInstance.describeThreshold(OVERRIDE.fail_on_severity)).toBe(
            'gate_policies.severity_rules.none'
        );
        expect(fixture.componentInstance.describeThreshold('high')).toBe('gate_policies.severity_rules.high');
    });

    it('shows a threshold it has no word for as sent, never as a key path', () => {
        load([OVERRIDE]);

        // Literal keys (decision 0019): the card built `severity_rules.${value}`; a threshold a
        // newer server stores would have read as a key, and "off" would have been a lie.
        expect(fixture.componentInstance.describeThreshold('negligible')).toBe('negligible');
        expect(missingFromBundles(Object.values(THRESHOLD_KEYS))).toEqual([]);
    });

    it('sends "none" for a rule switched off, and every field on every save', () => {
        load([]);

        fixture.componentInstance.editGlobal();
        fixture.componentInstance.draft.failOnSeverity = 'none';
        fixture.componentInstance.draft.failOnKev = true;
        fixture.componentInstance.save();

        const request = http.expectOne({ method: 'PUT', url: '/api/v1/gate/policies/global' });
        expect((request.request.body as GatePolicyRequest).fail_on_severity).toBe('none');
        // Every flag, always: the server refuses a partial policy rather than defaulting the
        // missing half, and a form that omitted one would only find out in production.
        expect((request.request.body as GatePolicyRequest).fail_on_kev).toBe(true);
        expect((request.request.body as GatePolicyRequest).fixable_only).toBe(false);
        expect((request.request.body as GatePolicyRequest).include_triaged).toBe(false);
        expect((request.request.body as GatePolicyRequest).include_ai_review).toBe(false);
        expect((request.request.body as GatePolicyRequest).fail_on_uncovered_languages).toBe(false);
        expect((request.request.body as GatePolicyRequest).include_plugins).toBe(false);
        request.flush({ ...GLOBAL, version: 1 });
    });

    /**
     * Plugin and imported findings count only when a policy includes them (decision 0017), and the
     * server reads an **absent** flag as off. The form used not to send it at all: a policy saved
     * with plugins switched on went back to "not counted" under a new version number, silently.
     */
    it('sends include_plugins, and keeps the stored value when a policy is edited', () => {
        load([{ ...GLOBAL, include_plugins: true }]);

        fixture.componentInstance.editGlobal();
        expect(fixture.componentInstance.draft.includePlugins).toBe(true);
        fixture.componentInstance.save();

        const request = http.expectOne({ method: 'PUT', url: '/api/v1/gate/policies/global' });
        expect((request.request.body as GatePolicyRequest).include_plugins).toBe(true);
        request.flush({ ...GLOBAL, include_plugins: true, version: 4 });
    });

    it('offers the plugins switch in the form, off for a new override', () => {
        load([GLOBAL]);

        fixture.componentInstance.addOverride();
        for (const request of http.match(() => true)) request.flush([]);
        fixture.detectChanges();

        // Through the DOM: a draft field no control is bound to would pass every component test.
        const toggle = document.querySelector('#policy-plugins');
        expect(toggle).not.toBeNull();
        expect(fixture.componentInstance.draft.includePlugins).toBe(false);
        expect(document.body.textContent).toContain('gate_policies.plugins_toggle');
    });

    it('says on the card whether plugin findings are counted', () => {
        load([{ ...GLOBAL, include_plugins: true }]);

        const text = (fixture.nativeElement as HTMLElement).textContent;
        expect(text).toContain('gate_policies.plugins');
        expect(text).toContain('gate_policies.builtin_plugins_note');
    });

    /**
     * The clause that fails on an examination rather than on a finding.
     *
     * <p>Off in the form as it is off in the code: a target no rule reaches reports nothing, and
     * nothing passes every policy. Turning it on is a deliberate act, and this is what says the
     * switch reaches the server rather than only the screen.
     */
    it('leaves the coverage clause off unless the operator turns it on', () => {
        load([]);

        fixture.componentInstance.editGlobal();
        expect(fixture.componentInstance.draft.failOnUncoveredLanguages).toBe(false);

        fixture.componentInstance.draft.failOnUncoveredLanguages = true;
        fixture.componentInstance.save();

        const request = http.expectOne({ method: 'PUT', url: '/api/v1/gate/policies/global' });
        expect((request.request.body as GatePolicyRequest).fail_on_uncovered_languages).toBe(true);
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

        fixture.componentInstance.remove(OVERRIDE);
        http.expectOne({ method: 'DELETE', url: '/api/v1/gate/policies/repository/5' }).flush(null);
        http.expectOne('/api/v1/gate/policies').flush({ policies: [GLOBAL], built_in: BUILT_IN });
        fixture.detectChanges();

        expect(fixture.componentInstance.overrides().length).toBe(0);
    });

    it("titles the dialog in the reader's language, after a switch too", () => {
        // The scope was translated once into a plain field: a dialog opened in English kept
        // "the global policy" in its French title after the reader switched language.
        useEnglish();
        load([]);
        fixture.componentInstance.editGlobal();
        fixture.detectChanges();
        const title = () => document.body.querySelector('[role="dialog"] .p-dialog-title')?.textContent?.trim();
        expect(title()).toBe('Policy for the global policy');

        useFrench();
        fixture.detectChanges();

        expect(title()).toBe('Politique pour la politique globale');
    });

    it("names an override whose target has no name by its kind in the reader's language", () => {
        // The server sends no name for a target deleted since; the row printed the stored kind,
        // "repository #12", in the French interface too.
        useEnglish();
        load([
            { ...OVERRIDE, target_name: null, target_id: 12 },
            { ...OVERRIDE, kind: 'container', target_name: null, target_id: 4 }
        ]);
        const names = () =>
            [...(fixture.nativeElement as HTMLElement).querySelectorAll('[data-testid="override-target"]')].map(
                (cell) => cell.textContent.trim()
            );
        const editLabels = () =>
            [...(fixture.nativeElement as HTMLElement).querySelectorAll('button[aria-label^="Edit"]')].map((button) =>
                button.getAttribute('aria-label')
            );

        expect(names()).toEqual(['Repository #12', 'Image #4']);
        expect(editLabels()).toEqual(['Edit the override for Repository #12', 'Edit the override for Image #4']);

        fixture.componentInstance.editOverride(fixture.componentInstance.overrides()[0]);
        fixture.detectChanges();
        const title = () => document.body.querySelector('[role="dialog"] .p-dialog-title')?.textContent?.trim();
        expect(title()).toBe('Policy for Repository #12');

        useFrench();
        fixture.detectChanges();
        expect(names()).toEqual(['Dépôt n° 12', 'Image n° 4']);
        expect(title()).toBe('Politique pour Dépôt n° 12');
    });

    it('keeps the name of a named target, and its number in the dialog title', () => {
        useEnglish();
        load([OVERRIDE]);

        expect(
            (fixture.nativeElement as HTMLElement).querySelector('[data-testid="override-target"]')?.textContent?.trim()
        ).toBe('Arm Libs Spring');
        fixture.componentInstance.editOverride(fixture.componentInstance.overrides()[0]);
        fixture.detectChanges();
        expect(document.body.querySelector('[role="dialog"] .p-dialog-title')?.textContent?.trim()).toBe(
            'Policy for Arm Libs Spring #5'
        );
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
        expect((fixture.nativeElement as HTMLElement).textContent).toContain('hgh');
    });
});
