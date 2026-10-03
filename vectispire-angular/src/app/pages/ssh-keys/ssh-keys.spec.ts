import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { SshKeys } from './ssh-keys';
import { asSchema, asSchemaList } from '@/app/core/testing/contract';

/**
 * The deployment keys screen, driven as an operator drives it: the buttons, the fields, the dialogs.
 *
 * <p>What it must not lose is the server's reason. A key that is not a private key, a server with no
 * encryption key, a key still used by repositories — each refusal names what to do, and a generic
 * "could not add" in its place leaves the operator guessing.
 */
describe('the SSH keys screen', () => {
    let fixture: ComponentFixture<SshKeys>;
    let http: HttpTestingController;

    const KEY = asSchema('SshKeySummary', {
        id: '7c2e9a10-4b1d-4f3a-8e55-0d6b2c9f1a37',
        name: 'deploy-payments',
        publicKey: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl deploy',
        createdAt: '2026-09-20T08:00:00Z',
        encryptionState: 'current',
        usedByRepositories: 3
    });

    beforeEach(async () => {
        await TestBed.configureTestingModule({
            imports: [SshKeys],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting()]
        }).compileComponents();

        fixture = TestBed.createComponent(SshKeys);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
    });

    function list(keys: unknown[] = [KEY]): void {
        http.expectOne((call) => call.method === 'GET' && call.url === '/api/v1/ssh-keys').flush(
            asSchemaList('SshKeySummary', keys)
        );
        fixture.detectChanges();
    }

    /** A button by its accessible name: its label, or its aria-label for an icon alone. */
    function button(name: string): HTMLButtonElement {
        const found = [...document.querySelectorAll<HTMLButtonElement>('button')].find(
            (candidate) => candidate.getAttribute('aria-label') === name || candidate.textContent.trim() === name
        );
        if (!found) throw new Error(`no button named ${name}`);
        return found;
    }

    function click(name: string): void {
        button(name).click();
        fixture.detectChanges();
    }

    function type(selector: string, value: string): void {
        const field = document.querySelector<HTMLInputElement | HTMLTextAreaElement>(selector)!;
        field.value = value;
        field.dispatchEvent(new Event('input'));
        fixture.detectChanges();
    }

    /** What the messages say; the info notice about generating a key is always among them. */
    function errorText(): string {
        return [...document.querySelectorAll('p-message')].map((message) => message.textContent).join(' ');
    }

    /** The confirmation dialog's Delete, the last on the page: the dialog's title says the same word. */
    function confirmDelete(): void {
        const deletes = [...document.querySelectorAll<HTMLButtonElement>('button')].filter(
            (candidate) => candidate.textContent.trim() === 'common.delete'
        );
        deletes[deletes.length - 1].click();
        fixture.detectChanges();
    }

    it('lists each key with its shortened public key and the repositories using it', () => {
        list();

        const row = fixture.nativeElement.querySelector('tbody tr') as HTMLElement;
        expect(row.textContent).toContain('deploy-payments');
        // 44 characters and an ellipsis: the whole line would crush every other column.
        expect(row.textContent).toContain(`${KEY.publicKey.slice(0, 44)}…`);
        expect(row.querySelector('[title]')?.getAttribute('title')).toBe(KEY.publicKey);
        expect(row.textContent).toContain('3');
    });

    it('badges each encryption state in words, and an unknown one as unreadable', () => {
        list([
            { ...KEY, id: 'a', name: 'old', encryptionState: 'previous_key' },
            { ...KEY, id: 'b', name: 'odd', encryptionState: 'sealed_by_hsm' }
        ]);

        // No bundle is loaded, so a tag shows its key: what matters is *which* — a literal one, and
        // for a state the client does not know, the unreadable one rather than a built path.
        const tags = [...fixture.nativeElement.querySelectorAll('tbody p-tag')].map((tag: Element) =>
            tag.textContent.trim()
        );
        expect(tags).toEqual(['ssh_keys.encryption_status.rotate', 'ssh_keys.encryption_status.unreadable']);
    });

    it('says when there is no key', () => {
        list([]);

        expect(fixture.nativeElement.textContent).toContain('ssh_keys.no_keys');
    });

    it('says the list could not be loaded', () => {
        http.expectOne('/api/v1/ssh-keys').flush(null, { status: 500, statusText: 'Server Error' });
        fixture.detectChanges();

        expect(errorText()).toContain('ssh_keys.error_load');
    });

    it('sends the typed key trimmed, without an empty public key, then reloads the list', () => {
        list([]);
        click('ssh_keys.add_key_btn');

        type('#name', ' deploy-payments ');
        type('#private', '  -----BEGIN OPENSSH PRIVATE KEY-----\n…\n-----END OPENSSH PRIVATE KEY-----\n');
        type('#public', '   ');
        click('common.create');

        const request = http.expectOne((call) => call.method === 'POST' && call.url === '/api/v1/ssh-keys');
        expect(request.request.body).toEqual({
            name: 'deploy-payments',
            private_key: '-----BEGIN OPENSSH PRIVATE KEY-----\n…\n-----END OPENSSH PRIVATE KEY-----',
            public_key: undefined
        });
        request.flush({ id: KEY.id });
        fixture.detectChanges();
        list();

        expect(fixture.componentInstance.formVisible()).toBe(false);
        expect(fixture.nativeElement.querySelector('tbody')?.textContent).toContain('deploy-payments');
    });

    it("keeps the dialog open on the server's refusal, and shows its reason", () => {
        list([]);
        click('ssh_keys.add_key_btn');
        type('#name', 'x');
        type('#private', 'not a key');
        click('common.create');

        http.expectOne((call) => call.method === 'POST').flush(
            { detail: 'This is not an OpenSSH or PEM private key.' },
            { status: 400, statusText: 'Bad Request' }
        );
        fixture.detectChanges();

        expect(document.querySelector('#private')).not.toBeNull();
        expect(errorText()).toContain('not an OpenSSH or PEM private key');
    });

    it('deletes a key once confirmed, from its named trash button', () => {
        list();
        click('ssh_keys.aria_delete');
        expect(document.body.textContent).toContain('ssh_keys.delete_confirm');

        confirmDelete();

        http.expectOne((call) => call.method === 'DELETE' && call.url === `/api/v1/ssh-keys/${KEY.id}`).flush(null);
        list([]);

        expect(fixture.nativeElement.textContent).toContain('ssh_keys.no_keys');
    });

    it('says why a key still in use cannot be deleted', () => {
        list();
        click('ssh_keys.aria_delete');
        confirmDelete();

        http.expectOne((call) => call.method === 'DELETE').flush(
            { detail: 'This key is used by 3 repositories.' },
            { status: 409, statusText: 'Conflict' }
        );
        fixture.detectChanges();

        expect(errorText()).toContain('used by 3 repositories');
    });
});
