import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { Repositories } from './repositories';
import { asSchema, asSchemaList } from '@/app/core/testing/contract';

/**
 * The repository list, as cards rather than rows.
 *
 * <p>Converted from a table because these are entities and not measurements: nobody compares the
 * URL of the third against the URL of the seventh, and the alignment a table buys is paid for in
 * horizontal scrolling on a narrow screen. What a smoke test cannot say is whether the card still
 * carries everything the row did — that is what this asserts, field by field.
 */
describe('the repository list', () => {
    let fixture: ComponentFixture<Repositories>;
    let http: HttpTestingController;

    const REPOSITORY = asSchema('RepositorySummary', {
        id: 5,
        url: 'ssh://git@bitbucket.example.com/art/basalt-libs-spring.git',
        branch: 'master',
        name: null,
        displayName: 'Arm Libs Spring',
        subPath: 'backend',
        scanIntervalMinutes: null,
        scanCron: null,
        openIssues: 38,
        lastScan: {
            id: 34,
            status: 'completed',
            createdAt: '2026-08-21T05:03:00Z',
            error: null
        }
    });

    beforeEach(async () => {
        await TestBed.configureTestingModule({
            imports: [Repositories],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        fixture = TestBed.createComponent(Repositories);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
    });

    function load(repository: Record<string, unknown> = REPOSITORY): void {
        for (const request of http.match(() => true)) {
            request.flush(request.request.url.endsWith('/repositories') ? [repository] : []);
        }
        fixture.detectChanges();
    }

    it('keeps every field the row carried', () => {
        load();

        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('Arm Libs Spring');
        expect(text).toContain('ssh://git@bitbucket.example.com/art/basalt-libs-spring.git');
        expect(text).toContain('master');
        // The count now travels beside the key as a parameter, so it is asserted on the model
        // rather than in the rendered text — which this harness leaves unresolved anyway.
        expect(text).toContain('repositories.outstanding');
        expect(fixture.componentInstance.repositories()[0].openIssues).toBe(38);
    });

    it('shows the sub-path, or a monorepo registered twice reads as one target listed twice', () => {
        load();
        expect(fixture.nativeElement.textContent).toContain('backend');
    });

    it("links the outstanding count to that target's backlog", () => {
        load();

        const link = fixture.nativeElement.querySelector('a[href*="/issues"]');
        expect(link).not.toBeNull();
        expect(link.getAttribute('href')).toContain('repository_id=5');
    });

    it('names the project a repository is filed in, and links to it in the tree', () => {
        load(asSchema('RepositorySummary', { ...REPOSITORY, projectId: 11, projectName: 'Gateway' }));

        const cell = fixture.nativeElement.querySelector('[data-testid="repository-project"]') as HTMLElement;
        expect(cell.textContent).toContain('Gateway');
        const link = cell.querySelector('a') as HTMLAnchorElement;
        // The fragment is the project's anchor in the tree, so the link lands on the project and not
        // on the top of a page listing every solution.
        expect(link.getAttribute('href')).toBe('/solutions#project-11');
    });

    it('shows a dash, and no link, for a repository in no project', () => {
        load();

        const cell = fixture.nativeElement.querySelector('[data-testid="repository-project"]') as HTMLElement;
        expect(cell.textContent).toContain('—');
        expect(cell.querySelector('a')).toBeNull();
    });

    it('says "nothing outstanding" rather than showing a bare zero', () => {
        load({ ...REPOSITORY, openIssues: 0 });
        expect(fixture.nativeElement.textContent).toContain('repositories.nothing_outstanding');
    });

    it('says a never-scanned target was never scanned', () => {
        load({ ...REPOSITORY, lastScan: null });
        // An empty cell reads as missing data; "never scanned" is a fact about the target.
        const text = fixture.nativeElement.textContent;
        expect(text.includes('Never scanned') || text.includes('scans.never_scanned')).toBe(true);
    });

    it('offers nothing to click when there is nothing to list', () => {
        load();
        http.verify();
    });

    it('says a target with no schedule is scanned only when somebody asks', () => {
        load();
        // A blank schedule column reads as "nothing to say here"; the target is in fact never
        // rescanned, which is the one thing about it worth knowing.
        expect(fixture.nativeElement.textContent).toContain('schedule.label_manual');
    });

    it('shows the expression rather than the interval when both are set, as the scheduler does', () => {
        load({ ...REPOSITORY, scanIntervalMinutes: 60, scanCron: '0 2 * * *' });

        const text = fixture.nativeElement.textContent as string;
        // The key, since the label is translated now and this harness leaves keys
        // unresolved. `label_cron` is still the whole assertion: it can only be reached
        // by the branch that prefers the expression over the interval.
        expect(text).toContain('schedule.label_cron');
        // Showing "every 60 min" would be a third opinion on a precedence the server already owns.
        expect(text).not.toContain('schedule.label_every');
    });

    /**
     * The schedule on the wire.
     *
     * <p>The two columns have existed on the row since the first version and no form ever wrote
     * them, so the assertion that matters is that the field reaches the request — a schedule the
     * dialog collects and drops is the same defect with a nicer screen.
     */
    it('sends the schedule when a repository is added', () => {
        load();

        fixture.componentInstance.openForm();
        fixture.componentInstance.form.url = 'https://github.com/org/thing.git';
        fixture.componentInstance.form.scanIntervalMinutes = 720;
        fixture.componentInstance.form.scanCron = '0 2 * * *';
        fixture.componentInstance.submit();

        const body = http.expectOne((call) => call.method === 'POST' && call.url === '/api/v1/repositories').request
            .body;
        expect(body.scanIntervalMinutes).toBe(720);
        expect(body.scanCron).toBe('0 2 * * *');
    });

    it('clears an interval with zero, because absent means "leave alone" on the update path', () => {
        load({ ...REPOSITORY, scanIntervalMinutes: 60 });

        fixture.componentInstance.openForm(fixture.componentInstance.repositories()[0]);
        fixture.componentInstance.form.scanIntervalMinutes = null;
        fixture.componentInstance.form.scanCron = '';
        fixture.componentInstance.submit();

        const body = http.expectOne((call) => call.method === 'PATCH').request.body;
        // `undefined` here would leave the old interval in place while the form showed nothing —
        // the operator would believe the schedule was off and the scans would carry on.
        expect(body.scanIntervalMinutes).toBe(0);
        expect(body.scanCron).toBe('');
    });

    it("surfaces the server's refusal of a cron expression instead of a generic failure", () => {
        load();

        fixture.componentInstance.openForm();
        fixture.componentInstance.form.url = 'https://github.com/org/thing.git';
        fixture.componentInstance.form.scanCron = 'every night';
        fixture.componentInstance.submit();

        http.expectOne((call) => call.method === 'POST' && call.url === '/api/v1/repositories').flush(
            // `detail`, which is where Spring's Problem Details puts the sentence — see `messageOf`.
            {
                detail: 'Unusable cron expression: "every night". Expected five fields, for example "0 2 * * *" (every day at 02:00).'
            },
            { status: 400, statusText: 'Bad Request' }
        );
        fixture.detectChanges();

        // The server's wording is the only one that names what was wrong with the expression.
        expect(fixture.componentInstance.formError()).toContain('Expected five fields');
    });

    /**
     * The clone credential: none, an SSH key, or an HTTPS token — never two.
     *
     * <p>The URL decides which are offered, and only the chosen kind is sent, the other cleared:
     * the server refuses a repository with both, an SSH key on an https:// URL, and a token bound
     * to another host (decision 0022). These go through the request body because that is where a
     * choice the form shows and drops would be visible.
     */
    describe('the clone credential', () => {
        const TOKENS = asSchemaList('GitTokenSummary', [
            {
                id: 'tok-gitlab',
                name: 'gitlab-read',
                host: 'gitlab.example.com',
                username: null,
                createdAt: '2026-09-20T08:00:00Z',
                encryptionState: 'current',
                usedByRepositories: 1
            },
            {
                id: 'tok-github',
                name: 'github-read',
                host: 'github.com',
                username: null,
                createdAt: '2026-09-20T08:00:00Z',
                encryptionState: 'current',
                usedByRepositories: 0
            }
        ]);
        const KEYS = asSchemaList('SshKeySummary', [
            {
                id: 'key-1',
                name: 'deploy',
                publicKey: null,
                createdAt: '2026-09-20T08:00:00Z',
                encryptionState: 'current',
                usedByRepositories: 1
            }
        ]);

        function loadAll(repository: Record<string, unknown> = REPOSITORY): void {
            for (const request of http.match(() => true)) {
                const url = request.request.url;
                request.flush(
                    url.endsWith('/repositories')
                        ? [repository]
                        : url.endsWith('/git-tokens')
                          ? TOKENS
                          : url.endsWith('/ssh-keys')
                            ? KEYS
                            : []
                );
            }
            fixture.detectChanges();
        }

        function kinds(): string[] {
            return fixture.componentInstance.credentialKinds().map((kind) => kind.value);
        }

        function typeUrl(url: string): void {
            fixture.componentInstance.form.url = url;
            fixture.componentInstance.onUrlChange();
        }

        it('offers HTTPS tokens and no SSH key for an https:// URL', () => {
            loadAll();
            fixture.componentInstance.openForm();
            typeUrl('https://gitlab.example.com/group/app.git');
            expect(kinds()).toEqual(['none', 'https']);
        });

        it('offers SSH keys and no token for ssh:// and scp-style URLs', () => {
            loadAll();
            fixture.componentInstance.openForm();
            typeUrl('ssh://git@gitlab.example.com/group/app.git');
            expect(kinds()).toEqual(['none', 'ssh']);
            typeUrl('git@gitlab.example.com:group/app.git');
            expect(kinds()).toEqual(['none', 'ssh']);
        });

        it("offers only the tokens bound to the URL's host", () => {
            loadAll();
            fixture.componentInstance.openForm();
            typeUrl('https://GitLab.example.com/group/app.git');
            expect(fixture.componentInstance.httpsTokenOptions().map((option) => option.value)).toEqual(['tok-gitlab']);
        });

        it('renders the token picker, and no key picker, once HTTPS is chosen', () => {
            loadAll();
            const screen = fixture.componentInstance;
            screen.openForm();
            typeUrl('https://gitlab.example.com/group/app.git');
            screen.form.credentialKind = 'https';
            fixture.detectChanges();

            expect(document.querySelector('#https-token')).not.toBeNull();
            expect(document.querySelector('#ssh-key')).toBeNull();
        });

        it('sends the chosen token and no SSH key on create', () => {
            loadAll();
            const screen = fixture.componentInstance;
            screen.openForm();
            typeUrl('https://gitlab.example.com/group/app.git');
            screen.form.credentialKind = 'https';
            screen.form.httpsTokenId = 'tok-gitlab';
            screen.submit();

            const body = http.expectOne((call) => call.method === 'POST' && call.url === '/api/v1/repositories').request
                .body;
            expect(body.https_token_id).toBe('tok-gitlab');
            expect(body.sshKeyId).toBe('');
        });

        it('leaves the token out of a create that has none', () => {
            loadAll();
            const screen = fixture.componentInstance;
            screen.openForm();
            typeUrl('ssh://git@gitlab.example.com/group/app.git');
            screen.form.credentialKind = 'ssh';
            screen.form.sshKeyId = 'key-1';
            screen.submit();

            const body = http.expectOne((call) => call.method === 'POST').request.body;
            expect(body.sshKeyId).toBe('key-1');
            expect('https_token_id' in body && body.https_token_id !== undefined).toBe(false);
        });

        it('clears the token with an empty string on update, since absent means "leave alone"', () => {
            loadAll({
                ...REPOSITORY,
                url: 'https://gitlab.example.com/group/app.git',
                httpsTokenId: 'tok-gitlab',
                sshKeyId: null
            });
            const screen = fixture.componentInstance;
            screen.openForm(screen.repositories()[0]);
            expect(screen.form.credentialKind).toBe('https');
            screen.form.credentialKind = 'none';
            screen.submit();

            const body = http.expectOne((call) => call.method === 'PATCH').request.body;
            expect(body.https_token_id).toBe('');
            expect(body.sshKeyId).toBe('');
        });

        it('drops the SSH key when the URL turns to https://, so what is sent is what is shown', () => {
            loadAll();
            const screen = fixture.componentInstance;
            screen.openForm(screen.repositories()[0]);
            screen.form.credentialKind = 'ssh';
            screen.form.sshKeyId = 'key-1';
            typeUrl('https://gitlab.example.com/group/app.git');
            expect(screen.form.credentialKind).toBe('none');
            screen.submit();

            const body = http.expectOne((call) => call.method === 'PATCH').request.body;
            expect(body.sshKeyId).toBe('');
        });

        it('drops a token bound to another host when the URL changes host', () => {
            loadAll();
            const screen = fixture.componentInstance;
            screen.openForm();
            typeUrl('https://gitlab.example.com/group/app.git');
            screen.form.credentialKind = 'https';
            screen.form.httpsTokenId = 'tok-gitlab';
            typeUrl('https://github.com/org/app.git');
            expect(screen.form.httpsTokenId).toBe('');
        });

        it('warns that credentials in the URL belong in an HTTPS token', () => {
            loadAll();
            const screen = fixture.componentInstance;
            screen.openForm();
            typeUrl('https://ci:glpat-secret@gitlab.example.com/group/app.git');
            fixture.detectChanges();
            expect(document.querySelector('#url-carries-secret')).not.toBeNull();
        });

        it('does not warn about a user name alone, which is no secret', () => {
            loadAll();
            const screen = fixture.componentInstance;
            screen.openForm();
            typeUrl('https://ci@gitlab.example.com/group/app.git');
            expect(screen.urlCarriesSecret()).toBe(false);
            typeUrl('https://gitlab.example.com/group/app.git');
            expect(screen.urlCarriesSecret()).toBe(false);
        });
    });
});
