import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { ForgeConnections } from './forge-connections';
import { useEnglish } from '@/app/core/testing/english';
import { asSchemaList } from '@/app/core/testing/contract';
import { missingFromBundles } from '@/app/core/testing/bundles';
import { CONNECTION, CONNECTION_ID } from '@/app/core/testing/forges.fixtures';
import {
    CA_PROBLEM_KEYS,
    CLONE_CREDENTIAL_KEYS,
    CREDENTIAL_KIND_KEYS,
    DISCOVERY_REASON_KEYS,
    DISCOVERY_STATE_KEYS,
    EDITION_KEYS,
    SKIP_REASON_KEYS,
    UNJUDGED_KEYS
} from '@/app/shared/forge-words';

const CERTIFICATE = '-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIU\n-----END CERTIFICATE-----';
const PRIVATE_KEY = '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----'; // gitleaks:allow

/**
 * The forge connections screen, through the DOM: what an administrator reads of a connection — whether its
 * token can write, when it expires, how the server is reached — and what the form sends, keeps and forgets.
 * Each of these can be right in the component and missing on screen.
 */
describe('the forge connections screen', () => {
    let fixture: ComponentFixture<ForgeConnections>;
    let http: HttpTestingController;

    const dom = () => fixture.nativeElement as HTMLElement;
    const text = (selector: string, root: ParentNode = dom()) =>
        root.querySelector(selector)?.textContent?.replace(/\s+/g, ' ').trim() ?? '';
    const field = <T extends Element>(selector: string) => document.querySelector<T>(selector);

    async function settle(): Promise<void> {
        fixture.detectChanges();
        await fixture.whenStable();
        fixture.detectChanges();
    }

    async function type(selector: string, value: string): Promise<void> {
        const input = field<HTMLInputElement | HTMLTextAreaElement>(selector)!;
        input.value = value;
        input.dispatchEvent(new Event('input'));
        await settle();
    }

    async function choose(selector: string, value: string): Promise<void> {
        const select = field<HTMLSelectElement>(selector)!;
        select.value = value;
        select.dispatchEvent(new Event('change'));
        await settle();
    }

    async function click(selector: string, root: ParentNode = document): Promise<void> {
        const host = root.querySelector<HTMLElement>(selector)!;
        (host.tagName === 'BUTTON' || host.tagName === 'INPUT' ? host : host.querySelector('button')!).click();
        await settle();
    }

    function list(connections: unknown[] = [CONNECTION]): void {
        http.expectOne({ method: 'GET', url: '/api/v1/forge-connections' }).flush(
            asSchemaList('ForgeConnectionView', connections)
        );
    }

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [ForgeConnections],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();
        useEnglish();
        fixture = TestBed.createComponent(ForgeConnections);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
    }, 20_000);

    it('spells every word of its vocabularies in both languages', () => {
        const maps = [
            DISCOVERY_STATE_KEYS,
            DISCOVERY_REASON_KEYS,
            SKIP_REASON_KEYS,
            EDITION_KEYS,
            CREDENTIAL_KIND_KEYS,
            CLONE_CREDENTIAL_KEYS,
            CA_PROBLEM_KEYS
        ];
        expect(missingFromBundles(maps.flatMap((map) => Object.values(map)))).toEqual([]);
        // Plural sentences are read through their `_one` form.
        expect(missingFromBundles(Object.values(UNJUDGED_KEYS).map((key) => `${key}_one`))).toEqual([]);
    });

    it('lists a connection with its token, its trust and what it discovered and imported', async () => {
        list();
        await settle();

        const card = dom().querySelector('[data-testid="connection"]')!;
        expect(text('[data-testid="connection-name"]', card)).toBe('Internal GitLab');
        expect(text('[data-testid="connection-edition"]', card)).toBe('GitLab self-managed or Dedicated');
        expect(text('[data-testid="connection-address"]', card)).toBe('https://gitlab.example.internal');
        expect(text('[data-testid="connection-token"]', card)).toBe('GitLab group or project token (read_api)');
        expect(text('[data-testid="connection-can-write"]', card)).toBe('Read-only');
        expect(text('[data-testid="connection-expiry"]', card)).toBe('2027-03-01');
        expect(text('[data-testid="connection-network"]', card)).toBe('Internal network');
        expect(text('[data-testid="connection-ca"]', card)).toBe('CN=Example Internal Root CA valid until 2030-01-01');
        expect(text('[data-testid="connection-last-discovery"]', card)).toContain('Completed');
        expect(text('[data-testid="connection-imported"]', card)).toBe('5');
        expect(card.querySelector('[data-testid="connection-discover"]')?.getAttribute('href')).toBe(
            `/forge-connections/${CONNECTION_ID}`
        );
    });

    it('says unknown when the forge does not report the permissions, and flags a token that can write', async () => {
        list([
            {
                ...CONNECTION,
                id: 'a1',
                edition: 'github_com',
                credentialKind: 'github_fine_grained',
                scopes: null,
                canWrite: null
            },
            {
                ...CONNECTION,
                id: 'a2',
                name: 'Enterprise Server',
                edition: 'github_enterprise_server',
                credentialKind: 'github_classic',
                scopes: ['repo'],
                canWrite: true
            }
        ]);
        await settle();

        const [fine, classic] = Array.from(dom().querySelectorAll('[data-testid="connection"]'));
        // Unknown is not "no": a fine-grained token is not shown read-only because nobody could check it.
        expect(text('[data-testid="connection-can-write"]', fine)).toBe('Not reported');
        expect(text('[data-testid="connection-token"]', fine)).toContain('grant it Metadata: read only');
        expect(text('[data-testid="connection-can-write"]', classic)).toBe('Can write');
    });

    it('tells a connection suspended by a disabled integration from an active one, naming the integration', async () => {
        list([
            { ...CONNECTION, id: 'c1' },
            { ...CONNECTION, id: 'c2', name: 'Suspended GitLab', state: 'suspended', integration: 'forge.gitlab' }
        ]);
        await settle();

        const [active, suspended] = Array.from(dom().querySelectorAll('[data-testid="connection"]'));
        expect(active.querySelector('[data-testid="connection-suspended"]')).toBeNull();
        expect(text('[data-testid="connection-suspended"]', suspended)).toBe('Suspended — integration disabled');
        // Everything it holds is still shown: a suspended connection is kept, not emptied.
        expect(text('[data-testid="connection-token"]', suspended)).toBe('GitLab group or project token (read_api)');
        expect(missingFromBundles(['forges.connections.suspended', 'forges.connections.suspended_hint'])).toEqual([]);
    });

    it('announces an expiry within fourteen days, and an expired token', async () => {
        const inDays = (days: number) => new Date(Date.now() + days * 86_400_000).toISOString();
        list([
            { ...CONNECTION, id: 'b1', tokenExpiresAt: inDays(5.5) },
            { ...CONNECTION, id: 'b2', tokenExpiresAt: inDays(-1) },
            { ...CONNECTION, id: 'b3', tokenExpiresAt: null }
        ]);
        await settle();

        const [soon, expired, none] = Array.from(dom().querySelectorAll('[data-testid="connection"]'));
        expect(text('[data-testid="connection-expiry"]', soon)).toContain('Expires in 6 days');
        expect(text('[data-testid="connection-expiry"]', expired)).toContain('Expired');
        expect(text('[data-testid="connection-expiry"]', none)).toBe('None reported');
    });

    it('says so when there is no connection yet', async () => {
        list([]);
        await settle();
        expect(text('[data-testid="no-connection"]')).toContain('No connection yet');
    });

    it('creates a connection to an internal GitLab with its CA, and forgets the token once saved', async () => {
        list();
        await settle();
        await click('[data-testid="add-connection"]', dom());

        await type('#forge-name', ' Internal GitLab ');
        await type('#forge-address', 'https://gitlab.example.internal');
        await type('#forge-token', 'glpat-secret'); // gitleaks:allow
        await click('#forge-internal');
        await type('#forge-ca', CERTIFICATE);
        expect(text('[data-testid="ca-feedback"]', document)).toContain('1 certificate read');

        await click('[data-testid="create-submit"]');
        const request = http.expectOne({ method: 'POST', url: '/api/v1/forge-connections' });
        expect(request.request.body).toEqual({
            kind: 'gitlab',
            name: 'Internal GitLab',
            baseUrl: 'https://gitlab.example.internal',
            owner: undefined,
            token: 'glpat-secret', // gitleaks:allow
            internalNetwork: true,
            caPem: CERTIFICATE
        });
        request.flush(CONNECTION, { status: 201, statusText: 'Created' });
        list();
        await settle();

        expect(fixture.componentInstance.createVisible()).toBe(false);
        expect(JSON.stringify(fixture.componentInstance.form)).not.toContain('glpat-secret'); // gitleaks:allow
    });

    it('names the owner for GitHub, and offers neither the internal network nor a CA for a cloud address', async () => {
        list();
        await settle();
        await click('[data-testid="add-connection"]', dom());

        await choose('#forge-kind', 'github');
        expect(field('#forge-owner')).not.toBeNull();
        // Blank is github.com: its host is public and its certificate a public CA's.
        expect(field('#forge-internal')).toBeNull();
        expect(field('#forge-ca')).toBeNull();
        expect(text('[data-testid="cloud-trust"]', document)).toContain('public CAs');

        await type('#forge-name', 'GitHub acme');
        await type('#forge-owner', 'acme');
        await type('#forge-token', 'github_pat_x'); // gitleaks:allow
        await click('[data-testid="create-submit"]');

        const body = http.expectOne({ method: 'POST', url: '/api/v1/forge-connections' }).request.body as Record<
            string,
            unknown
        >;
        expect(body['kind']).toBe('github');
        expect(body['owner']).toBe('acme');
        expect(body['baseUrl']).toBeUndefined();
        expect(body['internalNetwork']).toBe(false);
        expect(body['caPem']).toBeUndefined();
    });

    it('says in words what is wrong with a pasted CA, and does not send one it can see is wrong', async () => {
        list();
        await settle();
        await click('[data-testid="add-connection"]', dom());
        await type('#forge-address', 'https://gitlab.example.internal');
        const submit = () => document.querySelector<HTMLButtonElement>('[data-testid="create-submit"] button')!;

        await type('#forge-ca', PRIVATE_KEY);
        expect(text('[data-testid="ca-feedback"]', document)).toContain('This is a private key');
        expect(submit().disabled).toBe(true);

        await type('#forge-ca', 'not a certificate');
        expect(text('[data-testid="ca-feedback"]', document)).toContain('This is not a PEM certificate');

        await type('#forge-ca', '-----BEGIN CERTIFICATE-----\nMIIB');
        expect(text('[data-testid="ca-feedback"]', document)).toContain('A certificate is cut');

        await type('#forge-ca', Array.from({ length: 9 }, () => CERTIFICATE).join('\n'));
        expect(text('[data-testid="ca-feedback"]', document)).toContain('At most eight certificates');

        fixture.componentInstance.create();
        http.expectNone({ method: 'POST' });
    });

    it("shows the probe's refusal, keeps the form and clears the token", async () => {
        list();
        await settle();
        await click('[data-testid="add-connection"]', dom());
        expect(text('[data-testid="probe-explained"]', document)).toContain('older than GitLab 16');

        await type('#forge-name', 'Internal GitLab');
        await type('#forge-address', 'https://gitlab.example.internal');
        await type('#forge-token', 'glpat-broad'); // gitleaks:allow
        await click('[data-testid="create-submit"]');
        http.expectOne({ method: 'POST', url: '/api/v1/forge-connections' }).flush(
            {
                status: 400,
                title: 'Bad Request',
                detail: 'GitLab reports the scope api, which a connection may not hold.'
            },
            { status: 400, statusText: 'Bad Request' }
        );
        await settle();

        const refusal = text('[data-testid="create-error"]', document);
        expect(refusal).toContain('refused this connection');
        expect(refusal).toContain('reports the scope api');
        expect(fixture.componentInstance.createVisible()).toBe(true);
        expect(field<HTMLInputElement>('#forge-name')!.value).toBe('Internal GitLab');
        expect(fixture.componentInstance.form.token).toBe('');
    });

    it('replaces the token in place, and says the stored one is kept when the new one is refused', async () => {
        list();
        await settle();
        await click('[data-testid="connection-rotate"]', dom());
        await type('#forge-rotate-token', 'glpat-rotated'); // gitleaks:allow
        await click('[data-testid="rotate-submit"]');

        const request = http.expectOne({ method: 'PUT', url: `/api/v1/forge-connections/${CONNECTION_ID}/token` });
        expect(request.request.body).toEqual({ token: 'glpat-rotated' }); // gitleaks:allow
        request.flush({ detail: 'GitLab rejected the token (HTTP 401).' }, { status: 400, statusText: 'Bad Request' });
        await settle();

        expect(text('[data-testid="rotate-error"]', document)).toContain('GitLab rejected the token');
        expect(text('[data-testid="rotate-error"]', document)).toContain('The stored token is unchanged');
        expect(fixture.componentInstance.rotateToken).toBe('');
    });

    it('renames without touching the CA, and unpins it only when asked', async () => {
        list();
        await settle();
        await click('[data-testid="connection-edit"]', dom());
        await type('#forge-edit-name', 'GitLab (internal)');
        await click('[data-testid="edit-submit"]');

        // Absent keeps the CA: a rename that sent a blank would unpin it behind the administrator's back.
        const rename = http.expectOne({ method: 'PATCH', url: `/api/v1/forge-connections/${CONNECTION_ID}` });
        expect(rename.request.body).toEqual({ name: 'GitLab (internal)' });
        rename.flush(CONNECTION);
        list();
        await settle();

        await click('[data-testid="connection-edit"]', dom());
        await click('#forge-ca-unpin');
        await click('[data-testid="edit-submit"]');
        const unpin = http.expectOne({ method: 'PATCH', url: `/api/v1/forge-connections/${CONNECTION_ID}` });
        expect(unpin.request.body).toEqual({ caPem: '' });
        unpin.flush(CONNECTION);
        list();
    });

    it('deletes after a confirmation that says the imported targets are kept', async () => {
        list();
        await settle();
        await click('[data-testid="connection-delete"]', dom());

        const confirmation = text('[data-testid="delete-confirm"]', document);
        expect(confirmation).toContain('its 5 imported targets');
        expect(confirmation).toContain('The targets themselves are kept');

        await click('[data-testid="delete-submit"]');
        http.expectOne({ method: 'DELETE', url: `/api/v1/forge-connections/${CONNECTION_ID}` }).flush(null, {
            status: 204,
            statusText: 'No Content'
        });
        list([]);
        await settle();
        expect(fixture.componentInstance.deleting()).toBeNull();
    });
});
