import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { GitTokens } from './git-tokens';
import { asSchema, asSchemaList } from '@/app/core/testing/contract';

/**
 * The HTTPS tokens screen.
 *
 * <p>What matters beyond the list is where the secret goes: into one request body, and nowhere
 * after it. The form object outlives the dialog — it is only hidden — so a token left in it would
 * sit in memory, and in the input, until the page is closed.
 */
describe('the HTTPS tokens screen', () => {
    let fixture: ComponentFixture<GitTokens>;
    let http: HttpTestingController;

    const TOKEN = asSchema('GitTokenSummary', {
        id: '3b1f0c2e-6d4a-4e8b-9f10-2a7c5d9e1b44',
        name: 'gitlab-read',
        host: 'gitlab.example.com',
        username: 'oauth2',
        createdAt: '2026-09-20T08:00:00Z',
        encryptionState: 'current',
        usedByRepositories: 4
    });

    beforeEach(async () => {
        await TestBed.configureTestingModule({
            imports: [GitTokens],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        fixture = TestBed.createComponent(GitTokens);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
    });

    function list(tokens: unknown[] = [TOKEN]): void {
        http.expectOne((call) => call.method === 'GET' && call.url === '/api/v1/git-tokens').flush(
            asSchemaList('GitTokenSummary', tokens)
        );
        fixture.detectChanges();
    }

    it('lists each token with its host, username and the number of repositories using it', () => {
        list();

        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('gitlab-read');
        // The host is the token's boundary; a list without it would hide where it may be sent.
        expect(text).toContain('gitlab.example.com');
        expect(text).toContain('oauth2');
        expect(text).toContain('4');
    });

    it('offers the token as a password field, so it is not shown while typed', () => {
        list();
        fixture.componentInstance.openForm();
        fixture.detectChanges();

        const input = document.querySelector<HTMLInputElement>('#git-token-secret');
        expect(input).not.toBeNull();
        expect(input!.type).toBe('password');
    });

    it('sends the token once and forgets it after the save', () => {
        list();
        const screen = fixture.componentInstance;
        screen.openForm();
        screen.form = { name: ' gitlab-read ', host: ' gitlab.example.com ', username: '', token: ' glpat-secret ' };
        screen.submit();

        const request = http.expectOne((call) => call.method === 'POST' && call.url === '/api/v1/git-tokens');
        expect(request.request.body).toEqual({
            name: 'gitlab-read',
            host: 'gitlab.example.com',
            username: undefined,
            token: 'glpat-secret'
        });
        request.flush(TOKEN);
        list();

        expect(screen.form.token).toBe('');
        expect(JSON.stringify(screen.form)).not.toContain('glpat-secret');
        expect(screen.formVisible()).toBe(false);
    });

    it('forgets a token typed into a dialog that was cancelled', () => {
        list();
        const screen = fixture.componentInstance;
        screen.openForm();
        screen.form.token = 'glpat-abandoned';
        screen.closeForm();

        expect(screen.form.token).toBe('');
    });

    it("shows the server's refusal of a host, which knows what was wrong with it", () => {
        list();
        const screen = fixture.componentInstance;
        screen.openForm();
        screen.form = { name: 'x', host: 'https://gitlab.example.com', username: '', token: 't' };
        screen.submit();

        http.expectOne((call) => call.method === 'POST').flush(
            { detail: 'The host must be a bare host name, such as gitlab.example.com.' },
            { status: 400, statusText: 'Bad Request' }
        );

        expect(screen.formError()).toContain('bare host name');
        expect(screen.formVisible()).toBe(true);
    });

    it('deletes after confirmation, and says why when a repository still uses the token', () => {
        list();
        const screen = fixture.componentInstance;
        screen.askDelete(screen.tokens()[0]);
        expect(screen.deleteVisible()).toBe(true);
        screen.confirmDelete();

        http.expectOne((call) => call.method === 'DELETE' && call.url === `/api/v1/git-tokens/${TOKEN.id}`).flush(
            { detail: 'This token is used by 4 repositories.' },
            { status: 400, statusText: 'Bad Request' }
        );

        expect(screen.error()).toContain('used by 4 repositories');
    });
});
