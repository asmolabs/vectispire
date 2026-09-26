import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Solutions } from './solutions';
import { SessionStore } from '@/app/core/session.store';
import { asSchema } from '@/app/core/testing/contract';
import { useEnglish } from '@/app/core/testing/english';

/**
 * The solutions tree (decision 0023), through the DOM.
 *
 * <p>What is asserted is what a reader sees, because each of these can be right in the component and
 * wrong on screen: the "no project" group that must never disappear, the partial marker without
 * which half a project reads as the whole, the write actions a reader must not be offered, and the
 * sentences that tell an administrator a delete or a move takes something away from somebody.
 */
describe('the solutions tree', () => {
    let fixture: ComponentFixture<Solutions>;
    let http: HttpTestingController;

    const issues = (critical: number, high: number, medium = 0) =>
        asSchema('OpenIssues', {
            critical,
            high,
            medium,
            low: 0,
            negligible: 0,
            unknown: 0,
            total: critical + high + medium
        });

    const TREE = asSchema('SolutionTree', {
        solutions: [
            {
                id: 1,
                name: 'Payments',
                description: 'The payments platform',
                createdAt: '2026-09-01T00:00:00Z',
                partial: true,
                repositoryCount: 2,
                openIssues: issues(2, 1),
                projects: [
                    {
                        id: 11,
                        solutionId: 1,
                        name: 'Gateway',
                        description: null,
                        createdAt: '2026-09-01T00:00:00Z',
                        partial: true,
                        repositoryCount: 1,
                        openIssues: issues(2, 0),
                        repositories: [{ id: 9, name: 'api-gateway' }]
                    },
                    {
                        id: 12,
                        solutionId: 1,
                        name: 'Ledger',
                        description: null,
                        createdAt: '2026-09-01T00:00:00Z',
                        partial: false,
                        repositoryCount: 1,
                        openIssues: issues(0, 1),
                        repositories: [{ id: 10, name: 'ledger-core' }]
                    }
                ]
            },
            {
                id: 2,
                name: 'Mobile',
                description: null,
                createdAt: '2026-09-02T00:00:00Z',
                partial: false,
                repositoryCount: 0,
                openIssues: issues(0, 0),
                projects: [
                    {
                        id: 21,
                        solutionId: 2,
                        name: 'App',
                        description: null,
                        createdAt: '2026-09-02T00:00:00Z',
                        partial: false,
                        repositoryCount: 0,
                        openIssues: issues(0, 0),
                        repositories: []
                    }
                ]
            }
        ],
        unfiled: {
            repositoryCount: 1,
            openIssues: issues(0, 0, 4),
            repositories: [{ id: 30, name: 'legacy-batch' }]
        }
    });

    const EMPTY = asSchema('SolutionTree', {
        solutions: [],
        unfiled: { repositoryCount: 0, openIssues: issues(0, 0), repositories: [] }
    });

    function signIn(role: string): void {
        TestBed.inject(SessionStore).open('a-token', {
            username: role.toLowerCase(),
            displayName: null,
            role,
            mustChangePassword: false,
            mfaEnabled: false
        });
    }

    async function mount(role: string, tree: object = TREE): Promise<void> {
        signIn(role);
        fixture = TestBed.createComponent(Solutions);
        http = TestBed.inject(HttpTestingController);
        fixture.autoDetectChanges();
        http.expectOne((call) => call.method === 'GET' && call.url === '/api/v1/solutions').flush(tree);
        await fixture.whenStable();
    }

    const page = () => fixture.nativeElement as HTMLElement;
    const text = (selector: string) => document.querySelector(selector)?.textContent ?? '';
    const button = (name: string) =>
        [...document.querySelectorAll('button')].find((candidate) => candidate.getAttribute('aria-label') === name);

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Solutions],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();
        useEnglish();
    }, 20_000);

    it('draws solutions, their projects and their repositories, with counts and severities', async () => {
        await mount('USER');

        const payments = text('[data-testid="solution-1"]');
        expect(payments).toContain('Payments');
        expect(payments).toContain('The payments platform');
        expect(payments).toContain('Repositories: 2');
        expect(payments).toContain('2 Critical');
        expect(payments).toContain('1 High');

        const gateway = text('[data-testid="project-11"]');
        expect(gateway).toContain('Gateway');
        expect(gateway).toContain('api-gateway');
        expect(gateway).toContain('2 Critical');
        expect(gateway).not.toContain('High');

        // A node with nothing open says so, rather than showing no badge at all.
        expect(text('[data-testid="project-21"]')).toContain('No open issues');
    });

    it('marks a project seen only in part, in words, with what the reader can see', async () => {
        await mount('USER');

        // Half a project presented as the whole of it is a wrong figure that looks right.
        expect(text('[data-testid="project-11"] [data-testid="partial"]')).toContain(
            'Partially visible: 1 repositories you can see'
        );
        expect(document.querySelector('[data-testid="project-12"] [data-testid="partial"]')).toBeNull();
        expect(text('[data-testid="solution-1"]')).toContain('Partially visible: 2 repositories you can see');
    });

    it('shows "no project" last, with its repositories and figures', async () => {
        await mount('USER');

        const sections = [...page().querySelectorAll('section[data-testid]')].map((section) =>
            section.getAttribute('data-testid')
        );
        expect(sections.at(-1)).toBe('unfiled');

        const unfiled = text('[data-testid="unfiled"]');
        expect(unfiled).toContain('No project');
        expect(unfiled).toContain('legacy-batch');
        expect(unfiled).toContain('Repositories: 1');
        expect(unfiled).toContain('4 Medium');
    });

    it('keeps "no project" on screen when it is empty, and when there is no solution at all', async () => {
        await mount('USER', EMPTY);

        // A group that vanished when empty would read as "everything is filed" exactly when the
        // tree said nothing.
        expect(text('[data-testid="unfiled"]')).toContain('Every repository you can see is filed in a project.');
        expect(text('[data-testid="no-solutions"]')).toContain('No solution is visible to you yet.');
    });

    it('offers a reader no write action', async () => {
        await mount('USER');

        expect(document.querySelector('#new-solution')).toBeNull();
        expect(document.querySelector('[data-testid="new-project"]')).toBeNull();
        expect(button('Delete Gateway')).toBeUndefined();
        expect(button('Rename or describe Payments')).toBeUndefined();
        expect(button('File legacy-batch into a project')).toBeUndefined();
        expect(button('Move api-gateway to another project')).toBeUndefined();
    });

    it('offers an administrator every write action, each named for a screen reader', async () => {
        await mount('ADMIN');

        expect(document.querySelector('#new-solution')).not.toBeNull();
        expect(document.querySelectorAll('[data-testid="new-project"]')).toHaveLength(2);
        expect(button('Delete Payments')).toBeDefined();
        expect(button('Delete Gateway')).toBeDefined();
        expect(button('Rename or describe Gateway')).toBeDefined();
        expect(button('File legacy-batch into a project')).toBeDefined();
        expect(button('Move api-gateway to another project')).toBeDefined();
        expect(button('Remove api-gateway from its project')).toBeDefined();
    });

    it('says, before deleting a project, that its repositories are detached and its grants revoked', async () => {
        await mount('ADMIN');

        button('Delete Gateway')!.click();
        await fixture.whenStable();

        const confirmation = text('[data-testid="confirm-text"]');
        expect(confirmation).toContain('Payments / Gateway');
        expect(confirmation).toContain('return to “no project”');
        expect(confirmation).toContain('every grant naming this project is revoked');

        fixture.componentInstance.confirm();
        http.expectOne((call) => call.method === 'DELETE' && call.url === '/api/v1/projects/11').flush(null);
        http.expectOne((call) => call.method === 'GET' && call.url === '/api/v1/solutions').flush(TREE);
    });

    it("shows the server's refusal when a solution still holding projects is deleted", async () => {
        await mount('ADMIN');

        button('Delete Payments')!.click();
        await fixture.whenStable();
        fixture.componentInstance.confirm();

        http.expectOne((call) => call.method === 'DELETE' && call.url === '/api/v1/solutions/1').flush(
            { detail: 'The solution still holds 2 projects.' },
            { status: 409, statusText: 'Conflict' }
        );
        http.expectOne((call) => call.method === 'GET' && call.url === '/api/v1/solutions').flush(TREE);

        // The reload that follows must not take the explanation with it.
        await vi.waitFor(() => expect(page().textContent).toContain('The solution still holds 2 projects.'));
    });

    it('files an unfiled repository with the right ids, says it is an access change, and refreshes', async () => {
        await mount('ADMIN');

        button('File legacy-batch into a project')!.click();
        await fixture.whenStable();
        fixture.componentInstance.targetProjectId.set(12);
        await fixture.whenStable();

        expect(text('[data-testid="file-consequence"]')).toContain(
            'Filing legacy-batch into Payments / Ledger is an access change'
        );

        fixture.componentInstance.saveFile();
        const put = http.expectOne(
            (call) => call.method === 'PUT' && call.url === '/api/v1/projects/12/repositories/30'
        );
        put.flush(null);
        http.expectOne((call) => call.method === 'GET' && call.url === '/api/v1/solutions').flush(TREE);

        expect(fixture.componentInstance.fileVisible()).toBe(false);
    });

    it('says a move takes the repository from one project and gives it to the other', async () => {
        await mount('ADMIN');

        button('Move api-gateway to another project')!.click();
        await fixture.whenStable();

        // The project it is in is not offered as a destination.
        const offered = fixture.componentInstance.projectChoices().flatMap((group) => group.items.map((i) => i.value));
        expect(offered).toEqual([12, 21]);

        fixture.componentInstance.targetProjectId.set(21);
        await fixture.whenStable();

        const consequence = text('[data-testid="file-consequence"]');
        expect(consequence).toContain('Moving api-gateway changes who can see it');
        expect(consequence).toContain('Payments / Gateway');
        expect(consequence).toContain('Mobile / App');

        fixture.componentInstance.saveFile();
        http.expectOne((call) => call.method === 'PUT' && call.url === '/api/v1/projects/21/repositories/9').flush(
            null
        );
        http.expectOne((call) => call.method === 'GET' && call.url === '/api/v1/solutions').flush(TREE);
    });

    it('removes a repository from its project through the project it is in', async () => {
        await mount('ADMIN');

        button('Remove api-gateway from its project')!.click();
        await fixture.whenStable();
        expect(text('[data-testid="confirm-text"]')).toContain('Payments / Gateway');

        fixture.componentInstance.confirm();
        http.expectOne((call) => call.method === 'DELETE' && call.url === '/api/v1/projects/11/repositories/9').flush(
            null
        );
        http.expectOne((call) => call.method === 'GET' && call.url === '/api/v1/solutions').flush(TREE);
    });

    it('holds a name and a description to the server limits as they are typed', async () => {
        await mount('ADMIN');

        (document.querySelector('#new-solution button') as HTMLButtonElement).click();
        await fixture.whenStable();

        expect(document.querySelector('#node-name')?.getAttribute('maxlength')).toBe('100');
        expect(document.querySelector('#node-description')?.getAttribute('maxlength')).toBe('255');
    });

    it('creates a project in its solution, and keeps a refusal in the dialog', async () => {
        await mount('ADMIN');

        fixture.componentInstance.newProject(TREE.solutions[1]);
        fixture.componentInstance.formName.set('  Wallet  ');
        fixture.componentInstance.saveEditor();

        const post = http.expectOne((call) => call.method === 'POST' && call.url === '/api/v1/solutions/2/projects');
        expect(post.request.body).toEqual({ name: 'Wallet', description: '' });
        post.flush({ detail: 'Only an administrator may do this.' }, { status: 403, statusText: 'Forbidden' });

        expect(fixture.componentInstance.editorVisible()).toBe(true);
        expect(fixture.componentInstance.formError()).toBe('Only an administrator may do this.');
    });
});
