import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ActivatedRoute, Router, convertToParamMap, provideRouter } from '@angular/router';
import { describe, expect, it, vi } from 'vitest';
import { SessionStore } from '@/app/core/session.store';
import { asSchemaList } from '@/app/core/testing/contract';
import { useEnglish } from '@/app/core/testing/english';
import { ACTIVATION, MANIFEST, PLUGIN, WAIVED_PLUGIN } from '@/app/core/testing/plugins.fixtures';
import { Plugins, parseExitCodes } from './plugins';

/**
 * The plugin registry.
 *
 * **Three audiences on one page.** Every account reads it; the platform governor alone registers,
 * edits and enables; the projects a plugin reads are answered to governance readers only. The cases
 * below sign in as each and look at what the DOM offers — hiding is cosmetic, the server decides,
 * but a button that answers 403 is the broken screen this product has already shipped once.
 */
const RELEASE = 'https://github.com/acme/lint/.github/workflows/release.yml@refs/tags/v4.2.0';
const GITHUB = 'https://token.actions.githubusercontent.com';

describe('the plugin registry', () => {
    let fixture: ComponentFixture<Plugins>;
    let http: HttpTestingController;

    async function start(role: string, query: Record<string, string> = {}): Promise<void> {
        await TestBed.configureTestingModule({
            imports: [Plugins],
            providers: [
                provideHttpClient(withXhr()),
                provideHttpClientTesting(),
                provideRouter([]),
                { provide: ActivatedRoute, useValue: { snapshot: { queryParamMap: convertToParamMap(query) } } }
            ]
        }).compileComponents();
        TestBed.inject(SessionStore).open('token', {
            username: 'someone',
            displayName: null,
            role,
            mustChangePassword: false,
            mfaEnabled: false
        });
        vi.spyOn(TestBed.inject(Router), 'navigate').mockResolvedValue(true);
        useEnglish();
        fixture = TestBed.createComponent(Plugins);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        http.expectOne({ method: 'GET', url: '/api/v1/plugins' }).flush(asSchemaList('PluginView', [PLUGIN]));
        fixture.detectChanges();
    }

    const dom = () => fixture.nativeElement as HTMLElement;

    it('lists the registry to an ordinary account and offers it no change', async () => {
        await start('USER');

        expect(dom().textContent).toContain('acme-lint');
        expect(dom().textContent).toContain('ACME house rules');
        expect(dom().querySelector('#register-plugin')).toBeNull();
        expect(dom().querySelector('[aria-label="Edit the manifest of acme-lint"]')).toBeNull();
    });

    it('offers the governor registration, editing and disabling', async () => {
        await start('SUPERUSER');

        expect(dom().querySelector('#register-plugin')).not.toBeNull();
        expect(dom().querySelector('[aria-label="Edit the manifest of acme-lint"]')).not.toBeNull();
        expect(dom().textContent).toContain('Disable');
    });

    /** An administrator is not the governor: the server refuses them registration, so the page does. */
    it('does not offer registration to an administrator', async () => {
        await start('ADMIN');
        expect(dom().querySelector('#register-plugin')).toBeNull();
    });

    it('opens the plugin a link names, with every manifest field and its digest', async () => {
        await start('USER', { id: 'acme-lint' });

        http.expectOne('/api/v1/plugins/acme-lint').flush({
            ...PLUGIN,
            manifest: {
                ...MANIFEST,
                network: true,
                network_justification: 'Pulls rules from rules.acme.internal daily.'
            }
        });
        fixture.detectChanges();

        const detail = dom().querySelector('[data-testid="plugin-detail"]')?.textContent ?? '';
        expect(detail).toContain(MANIFEST.image);
        expect(detail).toContain('java, kotlin');
        expect(detail).toContain('{output}');
        expect(detail).toContain('0, 1');
        expect(detail).toContain('600 s');
        expect(detail).toContain('Pulls rules from rules.acme.internal daily.');
        expect(dom().querySelector('[data-testid="plugin-signer"]')?.textContent).toContain(
            'refused wherever a signer is required'
        );
        expect(dom().querySelector('[data-testid="manifest-digest"]')?.textContent).toContain(PLUGIN.manifestDigest);
        // An ordinary account is not answered which projects a plugin reads, and is not made to ask.
        http.expectNone('/api/v1/plugins/acme-lint/projects');
        expect(dom().querySelector('[data-testid="plugin-projects"]')).toBeNull();
    });

    it('shows a governance reader the projects the plugin reads, named by the activations themselves', async () => {
        await start('AUDITOR');

        fixture.componentInstance.open('acme-lint');
        http.expectOne('/api/v1/plugins/acme-lint').flush(PLUGIN);
        http.expectOne('/api/v1/plugins/acme-lint/projects').flush([
            ACTIVATION,
            // A project deleted between the read and its naming: the id is still the right answer.
            { ...ACTIVATION, id: 2, projectId: 99, projectName: null, solutionId: null, solutionName: null }
        ]);
        fixture.detectChanges();

        const items = Array.from(dom().querySelectorAll('[data-testid="plugin-projects"] li')).map((item) =>
            item.textContent?.replace(/\s+/g, ' ').trim()
        );
        expect(items[0]).toMatch(/^Payments \/ Gateway ·/);
        expect(items[1]).toMatch(/^#99 ·/);
        // The whole solution tree used to be loaded for these names.
        http.expectNone('/api/v1/solutions');
    });

    describe('the signature requirement', () => {
        const detail = (testid: string) => dom().querySelector(`[data-testid="${testid}"]`);

        async function opened(role: string, plugin = PLUGIN): Promise<void> {
            await start(role);
            fixture.componentInstance.open(plugin.id);
            http.expectOne('/api/v1/plugins/acme-lint').flush(plugin);
            if (fixture.componentInstance.readsGovernance()) {
                http.expectOne('/api/v1/plugins/acme-lint/projects').flush([]);
            }
            fixture.detectChanges();
        }

        it('says an unsigned plugin runs nowhere, and offers the waiver to the governor alone', async () => {
            await opened('USER');
            expect(detail('requirement-refused')?.textContent).toContain('refuses this plugin');
            expect(detail('open-waiver')).toBeNull();
            expect(detail('waiver-badge')).toBeNull();
        });

        it('does not offer the waiver to an administrator, whom the server refuses it', async () => {
            await opened('ADMIN');
            expect(detail('open-waiver')).toBeNull();
        });

        it('says a signed plugin is verified, and offers no waiver it would not need', async () => {
            await opened('SUPERUSER', {
                ...PLUGIN,
                manifest: { ...MANIFEST, signature: { identity: RELEASE, issuer: GITHUB, public_key: null } }
            });
            expect(detail('plugin-signature-requirement')?.textContent).toContain('verified with cosign');
            expect(detail('requirement-refused')).toBeNull();
            expect(detail('open-waiver')).toBeNull();
        });

        it('records the governor’s waiver with the justification as typed, trimmed, and shows it on the plugin', async () => {
            await opened('SUPERUSER');
            (detail('open-waiver')?.querySelector('button') as HTMLButtonElement).click();
            fixture.detectChanges();
            expect(fixture.componentInstance.waiverFor()?.id).toBe('acme-lint');

            fixture.componentInstance.waiverJustification =
                '  Built by our own CI; signing lands with the Q4 release pipeline.  ';
            fixture.componentInstance.saveWaiver();
            const request = http.expectOne({ method: 'PUT', url: '/api/v1/plugins/acme-lint/unsigned-waiver' });
            expect(request.request.body).toEqual({
                justification: 'Built by our own CI; signing lands with the Q4 release pipeline.'
            });
            request.flush(WAIVED_PLUGIN);
            fixture.detectChanges();

            expect(fixture.componentInstance.waiverFor()).toBeNull();
            expect(detail('waiver-badge')?.textContent).toContain('Runs unsigned (waiver)');
            expect(detail('waiver-justification')?.textContent).toContain('Q4 release pipeline');
            expect(detail('waiver-by')?.textContent).toContain('governor');
            expect(detail('requirement-refused')).toBeNull();
            expect(dom().textContent).toContain('acme-lint runs unsigned from the next scan');
        });

        it('keeps the server’s refusal of a short justification in the dialog', async () => {
            await opened('SUPERUSER');
            fixture.componentInstance.openWaiver(PLUGIN);
            fixture.componentInstance.waiverJustification = 'a sentence of twenty characters';
            fixture.componentInstance.saveWaiver();
            http.expectOne({ method: 'PUT', url: '/api/v1/plugins/acme-lint/unsigned-waiver' }).flush(
                { detail: 'Running a plugin unsigned needs its justification, written: 20 to 500 characters.' },
                { status: 400, statusText: 'Bad Request' }
            );
            fixture.detectChanges();

            expect(fixture.componentInstance.waiverFor()?.id).toBe('acme-lint');
            expect(document.querySelector('[data-testid="waiver-error"]')?.textContent).toContain('20 to 500');
            expect(detail('waiver-badge')).toBeNull();
        });

        it('shows a waiver and its justification to every reader, and lets the governor alone withdraw it', async () => {
            await opened('USER', WAIVED_PLUGIN);
            expect(detail('waiver-badge')).not.toBeNull();
            expect(detail('waiver-justification')?.textContent).toContain('Q4 release pipeline');
            expect(detail('revoke-waiver')).toBeNull();
        });

        it('withdraws the waiver with a DELETE, and the plugin reads as refused again', async () => {
            await opened('SUPERUSER', WAIVED_PLUGIN);
            (detail('revoke-waiver')?.querySelector('button') as HTMLButtonElement).click();
            http.expectOne({ method: 'DELETE', url: '/api/v1/plugins/acme-lint/unsigned-waiver' }).flush(PLUGIN);
            fixture.detectChanges();

            expect(detail('waiver-badge')).toBeNull();
            expect(detail('requirement-refused')).not.toBeNull();
            expect(dom().textContent).toContain('no longer runs unsigned');
        });
    });

    it('says an unknown id is unknown, rather than a failure to retry', async () => {
        await start('USER');

        fixture.componentInstance.open('nope');
        http.expectOne('/api/v1/plugins/nope').flush(null, { status: 404, statusText: 'Not Found' });
        fixture.detectChanges();

        expect(dom().textContent).toContain('No plugin is registered under “nope”.');
    });

    it('registers the whole manifest, and warns where the id is typed that it is permanent', async () => {
        await start('SUPERUSER');

        fixture.componentInstance.openRegister();
        fixture.detectChanges();
        expect(document.querySelector('[data-testid="id-permanent"]')?.textContent).toContain('can never be renamed');
        expect(document.querySelector('#plugin-id')).not.toBeNull();

        Object.assign(fixture.componentInstance.draft, {
            id: 'acme-lint',
            name: 'ACME house rules',
            image: MANIFEST.image,
            languages: ['java', 'kotlin'],
            arguments: ['--sarif', '{output}', '{source}'],
            exitCodes: '0, 1',
            timeoutSeconds: 600,
            // Typed, then the network switched back off: the justification must not travel alone.
            networkJustification: 'left over from an earlier idea',
            network: false
        });
        fixture.componentInstance.save();

        const request = http.expectOne({ method: 'POST', url: '/api/v1/plugins' });
        expect(request.request.body).toEqual(MANIFEST);
        request.flush(PLUGIN, { status: 201, statusText: 'Created' });
    });

    it("keeps the server's refusal in the dialog — a taken id is a 409 with its reason", async () => {
        await start('SUPERUSER');

        fixture.componentInstance.openRegister();
        Object.assign(fixture.componentInstance.draft, { id: 'acme-lint', name: 'x', image: MANIFEST.image });
        fixture.componentInstance.save();
        http.expectOne({ method: 'POST', url: '/api/v1/plugins' }).flush(
            { detail: 'A plugin "acme-lint" is already registered.' },
            { status: 409, statusText: 'Conflict' }
        );
        fixture.detectChanges();

        expect(fixture.componentInstance.formVisible()).toBe(true);
        expect(document.querySelector('[data-testid="plugin-form-error"]')?.textContent).toContain(
            'already registered'
        );
    });

    it('edits under the same id, which the form will not let anybody change', async () => {
        await start('SUPERUSER');

        fixture.componentInstance.openEdit(PLUGIN);
        fixture.detectChanges();
        await fixture.whenStable();
        fixture.detectChanges();
        expect((document.querySelector('#plugin-id') as HTMLInputElement).disabled).toBe(true);

        fixture.componentInstance.draft.name = 'ACME house rules v2';
        fixture.componentInstance.save();
        const request = http.expectOne({ method: 'PUT', url: '/api/v1/plugins/acme-lint' });
        expect(request.request.body.id).toBe('acme-lint');
        expect(request.request.body.name).toBe('ACME house rules v2');
        request.flush(PLUGIN);
    });

    it('disables through its own route and shows the answer', async () => {
        await start('SUPERUSER');

        fixture.componentInstance.setEnabled(PLUGIN, false);
        const request = http.expectOne({ method: 'PUT', url: '/api/v1/plugins/acme-lint/enabled' });
        expect(request.request.body).toEqual({ enabled: false });
        request.flush({ ...PLUGIN, enabled: false });
        fixture.detectChanges();

        expect(fixture.componentInstance.plugins()[0].enabled).toBe(false);
        expect(dom().textContent).toContain('acme-lint disabled');
    });

    it('shows who must have signed the image, keyless by identity and issuer', async () => {
        await start('USER', { id: 'acme-lint' });

        http.expectOne('/api/v1/plugins/acme-lint').flush({
            ...PLUGIN,
            manifest: { ...MANIFEST, signature: { identity: RELEASE, issuer: GITHUB, public_key: null } }
        });
        fixture.detectChanges();

        const signer = dom().querySelector('[data-testid="plugin-signer"]')?.textContent ?? '';
        expect(signer).toContain(`Keyless: ${RELEASE}, via ${GITHUB}`);
        expect(signer).not.toContain('trusted by its digest alone');
    });

    it('sends the signer as typed, and none at all when its three fields are empty', async () => {
        await start('SUPERUSER');

        fixture.componentInstance.openEdit({
            ...PLUGIN,
            manifest: { ...MANIFEST, signature: { identity: RELEASE, issuer: GITHUB, public_key: null } }
        });
        expect(fixture.componentInstance.draft.signerIdentity).toBe(RELEASE);
        expect(fixture.componentInstance.draft.signerIssuer).toBe(GITHUB);
        // A key pasted beside the identity travels with it: refusing both is the server's call, not the form's.
        fixture.componentInstance.draft.signerKey = '  -----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----\n';
        fixture.componentInstance.save();
        const edited = http.expectOne({ method: 'PUT', url: '/api/v1/plugins/acme-lint' });
        expect(edited.request.body.signature).toEqual({
            identity: RELEASE,
            issuer: GITHUB,
            public_key: '-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----'
        });
        edited.flush(PLUGIN);

        fixture.componentInstance.openEdit(PLUGIN);
        Object.assign(fixture.componentInstance.draft, { signerIdentity: '  ', signerIssuer: '', signerKey: '' });
        fixture.componentInstance.save();
        const unsigned = http.expectOne({ method: 'PUT', url: '/api/v1/plugins/acme-lint' });
        expect(unsigned.request.body.signature).toBeNull();
        unsigned.flush(PLUGIN);
    });

    it('refuses exit codes that are not integers before asking the server', async () => {
        await start('SUPERUSER');

        fixture.componentInstance.openRegister();
        fixture.componentInstance.draft.exitCodes = '0, one';
        fixture.componentInstance.save();
        http.expectNone({ method: 'POST', url: '/api/v1/plugins' });
        expect(fixture.componentInstance.formError()).toContain('whole numbers');
    });
});

describe('exit codes as typed', () => {
    it('reads a list, removes duplicates and defaults a blank to [0]', () => {
        expect(parseExitCodes('0, 1 1')).toEqual([0, 1]);
        expect(parseExitCodes('  ')).toEqual([0]);
        expect(parseExitCodes('0;1')).toBeNull();
    });
});
