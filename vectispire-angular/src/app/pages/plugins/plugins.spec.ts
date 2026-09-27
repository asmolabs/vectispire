import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ActivatedRoute, Router, convertToParamMap, provideRouter } from '@angular/router';
import { describe, expect, it, vi } from 'vitest';
import { SessionStore } from '@/app/core/session.store';
import { asSchemaList } from '@/app/core/testing/contract';
import { useEnglish } from '@/app/core/testing/english';
import { ACTIVATION, MANIFEST, PLUGIN } from '@/app/core/testing/plugins.fixtures';
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
            'trusted by its digest alone'
        );
        expect(dom().querySelector('[data-testid="manifest-digest"]')?.textContent).toContain(PLUGIN.manifestDigest);
        // An ordinary account is not answered which projects a plugin reads, and is not made to ask.
        http.expectNone('/api/v1/plugins/acme-lint/projects');
        expect(dom().querySelector('[data-testid="plugin-projects"]')).toBeNull();
    });

    it('shows a governance reader the projects the plugin reads, by name', async () => {
        await start('AUDITOR');

        fixture.componentInstance.open('acme-lint');
        http.expectOne('/api/v1/plugins/acme-lint').flush(PLUGIN);
        http.expectOne('/api/v1/plugins/acme-lint/projects').flush([ACTIVATION]);
        http.expectOne('/api/v1/solutions').flush({
            solutions: [{ id: 1, name: 'Payments', projects: [{ id: 12, name: 'Gateway' }] }],
            unfiled: null
        });
        fixture.detectChanges();

        expect(dom().querySelector('[data-testid="plugin-projects"]')?.textContent).toContain('Payments / Gateway');
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
