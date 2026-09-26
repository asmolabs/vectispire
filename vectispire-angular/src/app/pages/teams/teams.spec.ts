import { provideHttpClient, withXhr } from '@angular/common/http';
import { useEnglish } from '@/app/core/testing/english';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Teams } from './teams';
import { asSchema, asSchemaList } from '@/app/core/testing/contract';

/**
 * The team screen, which is the authorization model with a form on it.
 *
 * <p>A team is what grants an account sight of a target, so a mistake here is an authorization
 * mistake wearing a dialog. The cases below are the ones a person clicking through would not
 * find: the target identifiers are parsed out of `kind:id` strings by hand, and the save is two
 * requests that can half-succeed.
 */
describe('the teams screen', () => {
    let fixture: ComponentFixture<Teams>;
    let http: HttpTestingController;

    const TEAM = asSchema('TeamSummary', {
        id: 4,
        name: 'platform',
        description: null,
        memberCount: 1,
        targetCount: 2,
        notified: false
    });

    const ACCOUNTS = asSchema('UserListing', {
        users: [
            {
                id: 1,
                username: 'admin',
                email: null,
                displayName: 'The Administrator',
                role: 'ADMIN',
                isActive: true,
                mustChangePassword: false,
                createdAt: '2026-01-01T00:00:00Z',
                activeSessions: 1
            },
            {
                id: 2,
                username: 'reader',
                email: null,
                displayName: null,
                role: 'USER',
                isActive: true,
                mustChangePassword: false,
                createdAt: '2026-01-01T00:00:00Z',
                activeSessions: 0
            }
        ]
    });

    const TARGETS = asSchema('Targets', {
        repositories: [{ id: 7, label: 'ours' }],
        containers: [{ id: 3, label: 'registry.invalid/app:1.0' }]
    });

    /** One project to grant, named as the server names a project grant: "Solution / Project". */
    const openIssues = { critical: 0, high: 0, medium: 0, low: 0, negligible: 0, unknown: 0, total: 0 };
    const TREE = asSchema('SolutionTree', {
        solutions: [
            {
                id: 1,
                name: 'Payments',
                description: null,
                createdAt: '2026-09-01T00:00:00Z',
                partial: false,
                repositoryCount: 0,
                openIssues,
                projects: [
                    {
                        id: 11,
                        solutionId: 1,
                        name: 'Gateway',
                        description: null,
                        createdAt: '2026-09-01T00:00:00Z',
                        partial: false,
                        repositoryCount: 0,
                        openIssues,
                        repositories: []
                    }
                ]
            }
        ],
        unfiled: { repositoryCount: 0, openIssues, repositories: [] }
    });

    function settleBoot(accounts: object = ACCOUNTS): void {
        http.expectOne((call) => call.url === '/api/v1/teams').flush([TEAM]);
        http.expectOne((call) => call.url === '/api/v1/users').flush(accounts);
        http.expectOne((call) => call.url === '/api/v1/api-keys/targets').flush(TARGETS);
        http.expectOne((call) => call.url === '/api/v1/solutions').flush(TREE);
    }

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Teams],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        useEnglish();
        fixture = TestBed.createComponent(Teams);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
    }, 20_000);

    it('offers every account in the member picker, administrators included', () => {
        settleBoot();

        // An administrator is never restricted, so adding one changes nothing — but leaving them
        // out of the list makes the screen look broken to whoever goes looking for them.
        expect(fixture.componentInstance.accountOptions()).toEqual([
            { label: 'The Administrator', value: 1 },
            { label: 'reader', value: 2 }
        ]);
    });

    it("names each row's icon buttons after the team, for a screen reader", () => {
        settleBoot();
        fixture.detectChanges();

        // The pencil and the bin carried no text at all: a screen reader announced "button" twice
        // per row, and nothing said which team either would act on.
        const names = [...(fixture.nativeElement as HTMLElement).querySelectorAll('button')].map((button) =>
            button.getAttribute('aria-label')
        );
        expect(names).toContain('Rename platform');
        expect(names).toContain('Delete platform');
    });

    it('survives a users payload with no array in it', () => {
        // A server one version behind, or a proxy answering something else. Without the guard
        // this throws inside a computed signal, where the error handler never sees it.
        settleBoot({ unexpected: true });

        expect(fixture.componentInstance.accountOptions()).toEqual([]);
    });

    it('prefills the access dialog with what the team already grants', () => {
        settleBoot();
        fixture.componentInstance.openAccess(TEAM);

        http.expectOne((call) => call.url === '/api/v1/teams/4/members').flush([2]);
        http.expectOne((call) => call.url === '/api/v1/teams/4/targets').flush(
            asSchemaList('TargetGrant', [
                { kind: 'repository', id: 7, name: 'ours' },
                { kind: 'container', id: 3, name: 'registry.invalid/app:1.0' }
            ])
        );

        expect(fixture.componentInstance.selectedMembers()).toEqual([2]);
        // Held as `kind:id` strings because that is what the picker's option values are.
        expect(fixture.componentInstance.selectedTargets()).toEqual(['repository:7', 'container:3']);
    });

    /**
     * The same prefill, **as the administrator sees it.** The case above passed for as long as the
     * selection was a plain field written from the subscription — and in a zoneless application
     * nothing rendered it: the picker read "nobody yet", and saving what it showed emptied the
     * team. No `detectChanges` after the answers, since that is precisely what would hide it.
     */
    it('shows the prefilled members in the picker once they arrive', async () => {
        settleBoot();
        fixture.autoDetectChanges();
        fixture.componentInstance.openAccess(TEAM);
        await fixture.whenStable();

        const picker = () => document.querySelector('#team-members')?.closest('p-multiselect') as HTMLElement;
        expect(picker().textContent).not.toContain('reader');

        http.expectOne((call) => call.url === '/api/v1/teams/4/members').flush([2]);
        http.expectOne((call) => call.url === '/api/v1/teams/4/targets').flush([]);

        await vi.waitFor(() => expect(picker().textContent).toContain('reader'));
    });

    it('offers every project as a grant, named "Solution / Project"', () => {
        settleBoot();

        expect(fixture.componentInstance.targetOptions()).toContainEqual({
            label: 'Project — Payments / Gateway',
            value: 'project:11'
        });
    });

    /**
     * A project grant, **on screen and through the save.** The picker renders a selected value only
     * if an option carries it; a grant the dialog could not label would show as nothing ticked, and
     * saving the dialog as shown would revoke it. This one names a project the tree does not hold,
     * so only the server's name can label it.
     */
    it('shows a project grant by the name the server gives it, and keeps it on save', async () => {
        settleBoot();
        fixture.autoDetectChanges();
        const page = fixture.componentInstance;
        page.openAccess(TEAM);
        await fixture.whenStable();

        http.expectOne((call) => call.url === '/api/v1/teams/4/members').flush([2]);
        http.expectOne((call) => call.url === '/api/v1/teams/4/targets').flush(
            asSchemaList('TargetGrant', [
                { kind: 'project', id: 42, name: 'Mobile / App' },
                { kind: 'container', id: 3, name: 'registry.invalid/app:1.0' }
            ])
        );

        const picker = () => document.querySelector('#team-targets')?.closest('p-multiselect') as HTMLElement;
        await vi.waitFor(() => expect(picker().textContent).toContain('Project — Mobile / App'));

        page.saveAccess();
        http.expectOne((call) => call.method === 'PUT' && call.url === '/api/v1/teams/4/members').flush([2]);
        const targets = http.expectOne((call) => call.method === 'PUT' && call.url === '/api/v1/teams/4/targets');
        expect(targets.request.body).toEqual([
            { kind: 'project', id: 42 },
            { kind: 'container', id: 3 }
        ]);
        targets.flush([]);
        http.expectOne((call) => call.url === '/api/v1/teams').flush([TEAM]);
    });

    it('parses the identifiers back into numbers when saving', () => {
        settleBoot();
        const page = fixture.componentInstance;
        page.openAccess(TEAM);
        http.expectOne((call) => call.url === '/api/v1/teams/4/members').flush([]);
        http.expectOne((call) => call.url === '/api/v1/teams/4/targets').flush([]);

        page.selectedMembers.set([2]);
        page.selectedTargets.set(['repository:7', 'container:3']);
        page.saveAccess();

        http.expectOne((call) => call.method === 'PUT' && call.url === '/api/v1/teams/4/members').flush([2]);
        const targets = http.expectOne((call) => call.method === 'PUT' && call.url === '/api/v1/teams/4/targets');
        // A string id here is silently accepted by JSON and matches nothing on the server, so the
        // team would appear to grant a target it does not.
        expect(targets.request.body).toEqual([
            { kind: 'repository', id: 7 },
            { kind: 'container', id: 3 }
        ]);
        targets.flush([]);

        expect(page.accessVisible()).toBe(false);
        http.expectOne((call) => call.url === '/api/v1/teams').flush([TEAM]);
    });

    it('says which half applied when the targets fail after the members succeeded', () => {
        settleBoot();
        const page = fixture.componentInstance;
        page.openAccess(TEAM);
        http.expectOne((call) => call.url === '/api/v1/teams/4/members').flush([]);
        http.expectOne((call) => call.url === '/api/v1/teams/4/targets').flush([]);

        page.selectedMembers.set([2]);
        page.selectedTargets.set(['repository:7']);
        page.saveAccess();

        http.expectOne((call) => call.method === 'PUT' && call.url === '/api/v1/teams/4/members').flush([2]);
        http.expectOne((call) => call.method === 'PUT' && call.url === '/api/v1/teams/4/targets').flush(
            { message: 'nope' },
            { status: 500, statusText: 'Server Error' }
        );

        // The dialog stays open and names the half that applied. "Could not save" would leave an
        // administrator to guess whether the membership change took effect — and it did.
        expect(page.accessVisible()).toBe(true);
        expect(page.formError()).toContain('membership was saved');
        expect(page.saving()).toBe(false);
    });
});
