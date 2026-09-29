import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Solutions } from './solutions';
import { SessionStore } from '@/app/core/session.store';
import { asSchema } from '@/app/core/testing/contract';
import { useEnglish } from '@/app/core/testing/english';
import { ACTIVATION, PLUGIN } from '@/app/core/testing/plugins.fixtures';
import type { Plugin } from '@/app/core/api.models';

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
                        repositories: [{ id: 9, name: 'api-gateway' }],
                        detectedLanguages: [],
                        languagesUnknownFor: []
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
                        repositories: [{ id: 10, name: 'ledger-core' }],
                        detectedLanguages: [],
                        languagesUnknownFor: []
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
                        repositories: [],
                        detectedLanguages: [],
                        languagesUnknownFor: []
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

    it('links a project seen whole to its security checklist, and a partial one to nothing: it would answer 404', async () => {
        await mount('AUDITOR');

        const ledger = page().querySelector('[data-testid="project-12"] [data-testid="project-checklist"]');
        expect(ledger?.getAttribute('href')).toBe('/projects/12/checklist');
        expect(ledger?.getAttribute('aria-label')).toBe('Security checklist of Ledger');
        expect(page().querySelector('[data-testid="project-21"] [data-testid="project-checklist"]')).not.toBeNull();
        expect(page().querySelector('[data-testid="project-11"] [data-testid="project-checklist"]')).toBeNull();
    });

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

    /**
     * A figure opens the list it counts. Read from the anchors' `href`, because that is what a click
     * follows: a badge whose link dropped `unsettled` would open "3 high" onto a list of five.
     */
    it('links each severity badge of a solution and a project to that severity, that scope, unsettled only', async () => {
        await mount('USER');

        const links = (selector: string) =>
            [...page().querySelectorAll(`${selector} [data-testid="open-issues-link"]`)].map((anchor) => ({
                href: anchor.getAttribute('href'),
                name: anchor.getAttribute('aria-label')
            }));

        // The solution's own badges, and not its projects' (which sit inside the same section).
        const solution = links('[data-testid="solution-1"] > div');
        expect(solution).toEqual([
            {
                href: '/issues?solution_id=1&severity=critical&unsettled=true',
                name: 'Open the issues of critical severity in Payments (2)'
            },
            {
                href: '/issues?solution_id=1&severity=high&unsettled=true',
                name: 'Open the issues of high severity in Payments (1)'
            }
        ]);
        expect(links('[data-testid="project-12"]')).toEqual([
            {
                href: '/issues?project_id=12&severity=high&unsettled=true',
                name: 'Open the issues of high severity in Payments / Ledger (1)'
            }
        ]);

        // "No project" has no filter on the list: its figures stay figures rather than opening a
        // list that would disagree with them.
        expect(text('[data-testid="unfiled"]')).toContain('4 Medium');
        expect(links('[data-testid="unfiled"]')).toEqual([]);
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

    /**
     * A taken name is a 409 with a type, created, renamed or moved alike — a create or a rename used to
     * answer 400 — and the dialog says it in the screen's language rather than the server's English.
     */
    describe('a name already taken', () => {
        const conflict = (type: string, detail: string) => ({ type, title: 'Conflict', status: 409, detail });

        it('names the solution a project name is taken in, on a create and on a rename', async () => {
            await mount('ADMIN');

            fixture.componentInstance.newProject(TREE.solutions[0]);
            fixture.componentInstance.formName.set('ledger');
            fixture.componentInstance.saveEditor();
            http.expectOne((call) => call.method === 'POST' && call.url === '/api/v1/solutions/1/projects').flush(
                conflict(
                    'urn:vectispire:problem:project-name-taken',
                    'This solution already holds a project named "ledger".'
                ),
                { status: 409, statusText: 'Conflict' }
            );
            expect(fixture.componentInstance.editorVisible()).toBe(true);
            expect(fixture.componentInstance.formError()).toBe(
                'Payments already holds a project named ledger. Choose another name.'
            );

            fixture.componentInstance.editProject(TREE.solutions[0], TREE.solutions[0].projects[0]);
            fixture.componentInstance.formName.set('Ledger');
            fixture.componentInstance.saveEditor();
            http.expectOne((call) => call.method === 'PATCH' && call.url === '/api/v1/projects/11').flush(
                conflict(
                    'urn:vectispire:problem:project-name-taken',
                    'This solution already holds a project named "Ledger".'
                ),
                { status: 409, statusText: 'Conflict' }
            );
            expect(fixture.componentInstance.formError()).toBe(
                'Payments already holds a project named Ledger. Choose another name.'
            );
        });

        it('says a solution name is taken, and leaves any other conflict in the server words', async () => {
            await mount('ADMIN');

            fixture.componentInstance.newSolution();
            fixture.componentInstance.formName.set('mobile');
            fixture.componentInstance.saveEditor();
            http.expectOne((call) => call.method === 'POST' && call.url === '/api/v1/solutions').flush(
                conflict('urn:vectispire:problem:solution-name-taken', 'A solution named "mobile" already exists.'),
                { status: 409, statusText: 'Conflict' }
            );
            expect(fixture.componentInstance.formError()).toBe(
                'A solution named mobile already exists. Choose another name.'
            );

            fixture.componentInstance.editSolution(TREE.solutions[1]);
            fixture.componentInstance.formName.set('Mobile apps');
            fixture.componentInstance.saveEditor();
            http.expectOne((call) => call.method === 'PATCH' && call.url === '/api/v1/solutions/2').flush(
                { title: 'Conflict', status: 409, detail: 'Somebody changed this solution.' },
                { status: 409, statusText: 'Conflict' }
            );
            expect(fixture.componentInstance.formError()).toBe('Somebody changed this solution.');
        });
    });

    /**
     * A project moves to another solution with everything it holds. The request carries
     * `solutionId` and nothing it was not asked to change; a name taken in the destination keeps
     * the dialog open with the way out beside it.
     */
    describe('moving a project to another solution', () => {
        const PROJECT_NAME_TAKEN = {
            type: 'urn:vectispire:problem:project-name-taken',
            title: 'Conflict',
            status: 409,
            detail: 'A project with this name already exists in this solution.'
        };
        const confirmButton = () => document.querySelector('#move-project-confirm button') as HTMLButtonElement;

        async function openMove(): Promise<void> {
            await mount('ADMIN');
            button('Move Gateway to another solution')!.click();
            await fixture.whenStable();
        }

        async function typeName(value: string): Promise<void> {
            const input = document.querySelector('#move-name') as HTMLInputElement;
            input.value = value;
            input.dispatchEvent(new Event('input'));
            await fixture.whenStable();
        }

        it('is not offered to an account that is not an administrator', async () => {
            await mount('CISO');

            expect(button('Move Gateway to another solution')).toBeUndefined();
            expect(document.querySelector('[data-testid="move-project"]')).toBeNull();
        });

        it('offers only the other solutions, so a move that changes nothing cannot be chosen', async () => {
            await openMove();

            expect(fixture.componentInstance.solutionChoices()).toEqual([{ label: 'Mobile', value: 2 }]);
            expect(confirmButton().disabled).toBe(true);
        });

        it('sends solutionId alone, refreshes the tree and says where the project went', async () => {
            await openMove();
            fixture.componentInstance.targetSolutionId.set(2);
            await fixture.whenStable();
            confirmButton().click();

            const patch = http.expectOne((call) => call.method === 'PATCH' && call.url === '/api/v1/projects/11');
            expect(patch.request.body).toEqual({ solutionId: 2 });
            patch.flush(
                asSchema('ProjectView', {
                    id: 11,
                    solutionId: 2,
                    name: 'Gateway',
                    description: null,
                    createdAt: '2026-09-01T00:00:00Z'
                })
            );
            http.expectOne((call) => call.method === 'GET' && call.url === '/api/v1/solutions').flush(TREE);
            await fixture.whenStable();

            expect(fixture.componentInstance.moveVisible()).toBe(false);
            expect(text('[data-testid="notice"]')).toContain('Project Gateway moved to solution Mobile.');
        });

        it('keeps the dialog open on a name taken in the destination, and sends the new name on the retry', async () => {
            await openMove();
            fixture.componentInstance.targetSolutionId.set(2);
            await fixture.whenStable();
            confirmButton().click();
            http.expectOne((call) => call.method === 'PATCH' && call.url === '/api/v1/projects/11').flush(
                PROJECT_NAME_TAKEN,
                { status: 409, statusText: 'Conflict' }
            );
            await fixture.whenStable();

            expect(fixture.componentInstance.moveVisible()).toBe(true);
            expect(text('[data-testid="move-name-taken"]')).toContain(
                'Mobile already holds a project named Gateway. Give it another name above'
            );
            // The generic refusal is not shown beside it: the server's sentence names no way out.
            expect(fixture.componentInstance.formError()).toBeNull();
            http.expectNone((call) => call.method === 'GET' && call.url === '/api/v1/solutions');

            await typeName('  Gateway EU  ');
            confirmButton().click();
            const retry = http.expectOne((call) => call.method === 'PATCH' && call.url === '/api/v1/projects/11');
            expect(retry.request.body).toEqual({ solutionId: 2, name: 'Gateway EU' });
        });

        it('shows any other refusal as the server words it', async () => {
            await openMove();
            fixture.componentInstance.targetSolutionId.set(2);
            await fixture.whenStable();
            confirmButton().click();
            http.expectOne((call) => call.method === 'PATCH' && call.url === '/api/v1/projects/11').flush(
                { detail: 'Solution not found.', status: 404 },
                { status: 404, statusText: 'Not Found' }
            );
            await fixture.whenStable();

            expect(document.querySelector('[data-testid="move-name-taken"]')).toBeNull();
            expect(fixture.componentInstance.formError()).toBe('Solution not found.');
        });
    });

    /**
     * Plugins per project (decision 0017): which plugins a project runs is governance — read by its
     * readers, changed by a security lead. The dialog lists the whole registry beside the project's
     * activations, with each plugin's languages, so what would run is visible before the switch.
     */
    describe('plugins per project', () => {
        const OTHER: Plugin = {
            ...PLUGIN,
            id: 'py-rules',
            name: 'Python rules',
            enabled: false,
            manifest: { ...PLUGIN.manifest, id: 'py-rules', languages: ['python'] }
        };

        async function openFor(role: string, tree: object = TREE): Promise<void> {
            await mount(role, tree);
            (
                page().querySelector('[data-testid="project-11"] [data-testid="project-plugins"] button') as HTMLElement
            ).click();
            http.expectOne('/api/v1/plugins').flush([PLUGIN, OTHER]);
            http.expectOne('/api/v1/projects/11/plugins').flush([{ ...ACTIVATION, projectId: 11 }]);
            await fixture.whenStable();
        }

        const toggle = (id: string) =>
            document.querySelector<HTMLInputElement>(`[data-testid="project-plugin-${id}"] input`);

        it('is not offered to an account that cannot read governance', async () => {
            await mount('USER');
            expect(page().querySelector('[data-testid="project-plugins"]')).toBeNull();
        });

        it('shows an auditor what runs, with the languages, and lets it change nothing', async () => {
            await openFor('AUDITOR');

            const row = text('[data-testid="project-plugin-acme-lint"]');
            expect(row).toContain('acme-lint');
            expect(row).toContain('java');
            expect(row).toContain('kotlin');
            expect(toggle('acme-lint')?.checked).toBe(true);
            expect(toggle('py-rules')?.checked).toBe(false);
            expect(toggle('acme-lint')?.disabled).toBe(true);
            expect(text('[data-testid="plugins-dialog"]')).toContain('Only an administrator, the CISO');
            // A disabled plugin's switch may read "on" and run nothing; the row says so.
            expect(text('[data-testid="project-plugin-py-rules"]')).toContain('Disabled on the platform');
        });

        it('lets a CISO switch one on with a PUT and off with a DELETE', async () => {
            await openFor('CISO');
            expect(toggle('py-rules')?.disabled).toBe(false);

            fixture.componentInstance.togglePlugin(OTHER, true);
            http.expectOne({ method: 'PUT', url: '/api/v1/projects/11/plugins/py-rules' }).flush({
                ...ACTIVATION,
                pluginId: 'py-rules',
                projectId: 11
            });
            fixture.componentInstance.togglePlugin(PLUGIN, false);
            http.expectOne({ method: 'DELETE', url: '/api/v1/projects/11/plugins/acme-lint' }).flush(null);
            await fixture.whenStable();

            expect([...fixture.componentInstance.activations().keys()]).toEqual(['py-rules']);
        });

        /** The tree with project 11 carrying the given languages and the given uncounted repositories. */
        const withLanguages = (detectedLanguages: string[], languagesUnknownFor: number[]) => ({
            ...TREE,
            solutions: TREE.solutions.map((solution) => ({
                ...solution,
                projects: solution.projects.map((project) =>
                    project.id === 11
                        ? {
                              ...project,
                              repositoryCount: 2,
                              repositories: [
                                  { id: 9, name: 'api-gateway' },
                                  { id: 13, name: 'gateway-ui' }
                              ],
                              detectedLanguages,
                              languagesUnknownFor
                          }
                        : project
                )
            }))
        });
        const matched = (id: string) =>
            [...document.querySelectorAll(`[data-testid="project-plugin-${id}"] p-tag[data-matched]`)].map((tag) =>
                tag.textContent?.trim()
            );

        it("highlights the plugin's languages the project holds, and says it of a disjoint one", async () => {
            await openFor('AUDITOR', withLanguages(['java', 'typescript'], []));

            expect(matched('acme-lint')).toEqual(['java']);
            expect(text('[data-testid="project-plugin-acme-lint"]')).toContain('Present in this project: java.');
            expect(matched('py-rules')).toEqual([]);
            expect(text('[data-testid="project-plugin-py-rules"]')).toContain(
                'No language of this project: it would report not applicable'
            );
            expect(text('[data-testid="plugins-project-languages"]')).toContain('typescript');
            expect(document.querySelector('[data-testid="plugins-languages-unknown"]')).toBeNull();
        });

        it('informs and never blocks: a disjoint plugin can still be switched on', async () => {
            await openFor('CISO', withLanguages(['java'], []));
            expect(text('[data-testid="project-plugin-py-rules"]')).toContain('No language of this project');
            expect(toggle('py-rules')?.disabled).toBe(false);
        });

        it('names the repositories not yet counted, and does not call a plugin disjoint on their account', async () => {
            await openFor('AUDITOR', withLanguages(['java'], [13]));

            const note = text('[data-testid="plugins-languages-unknown"]');
            expect(note).toContain('(1)');
            expect(note).toContain('gateway-ui');
            expect(note).not.toContain('api-gateway');
            expect(text('[data-testid="project-plugin-py-rules"]')).toContain('those not yet scanned may hold one');
            expect(text('[data-testid="project-plugin-py-rules"]')).not.toContain('No language of this project');
        });

        it('says "not yet known" of a project nobody has counted', async () => {
            await openFor('AUDITOR', withLanguages([], [9, 13]));
            expect(text('[data-testid="plugins-project-languages"]')).toContain('not yet known');
            expect(text('[data-testid="plugins-project-languages"]')).not.toContain('no language detected');
            expect(text('[data-testid="plugins-languages-unknown"]')).toContain('(2)');
        });

        it('says "no language detected" of a project counted with none', async () => {
            await openFor('AUDITOR', withLanguages([], []));
            expect(text('[data-testid="plugins-project-languages"]')).toContain('no language detected');
            expect(text('[data-testid="plugins-project-languages"]')).not.toContain('not yet known');
        });

        it("shows a project's languages in the tree, and nothing where none is known", async () => {
            await mount('USER', withLanguages(['java', 'typescript'], [13]));
            expect(text('[data-testid="project-11"] [data-testid="project-languages"]')).toContain('typescript');
            expect(page().querySelector('[data-testid="project-12"] [data-testid="project-languages"]')).toBeNull();
        });

        it("keeps the stored state and the server's reason when a switch is refused", async () => {
            await openFor('CISO');

            fixture.componentInstance.togglePlugin(OTHER, true);
            http.expectOne({ method: 'PUT', url: '/api/v1/projects/11/plugins/py-rules' }).flush(
                { detail: 'Only a security lead may switch a plugin on.' },
                { status: 403, statusText: 'Forbidden' }
            );
            await fixture.whenStable();

            expect(fixture.componentInstance.activations().has('py-rules')).toBe(false);
            expect(text('[data-testid="plugins-dialog"]')).toContain('Only a security lead may switch a plugin on.');
        });
    });
});
