import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { Users } from './users';
import { asSchema, asSchemaList } from '@/app/core/testing/contract';

/**
 * The account screen, and the refusal it must not swallow.
 *
 * <p>The server refuses some changes by rule rather than by fault — demoting the last active
 * administrator, deactivating your own account. The screen reloads the list after a refusal so
 * the role selector stops showing the value that was rejected, and that reload used to erase the
 * message explaining why. The button then looked as though it did nothing at all. Only a spec
 * pins that pair together.
 */
describe('the accounts screen', () => {
    let fixture: ComponentFixture<Users>;
    let http: HttpTestingController;

    const account = (id: number, username: string, role: string, isActive = true) =>
        asSchema('UserAdminSummary', {
            id,
            username,
            email: null,
            displayName: null,
            role,
            isActive,
            mustChangePassword: false,
            createdAt: '2026-01-01T00:00:00Z',
            activeSessions: 0
        });

    const LIST = asSchema('UserListing', {
        users: [account(1, 'admin', 'ADMIN'), account(2, 'reader', 'USER')],
        currentUserId: 1
    });

    const TARGETS = asSchema('Targets', {
        repositories: [{ id: 7, label: 'helios-portal' }],
        containers: [{ id: 3, label: 'registry/service:1.4' }]
    });

    /** Restricted mode, which is a fresh installation's default. */
    const SETTINGS = asSchema('Catalog', {
        settings: [
            {
                key: 'target_visibility',
                value: 'assigned',
                configured: true,
                governor_only: false,
                administrator_only: false
            }
        ]
    });

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Users],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        fixture = TestBed.createComponent(Users);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        http.expectOne((call) => call.url === '/api/v1/users').flush(LIST);

        // The target list and the visibility mode, asked for by the constructor for the visibility
        // dialog. Emptied here so cases that are not about them stay readable — and the default is
        // restricted mode, the one where the assignments count.
        http.expectOne((call) => call.url === '/api/v1/api-keys/targets').flush(TARGETS);
        http.expectOne((call) => call.url === '/api/v1/settings').flush(SETTINGS);
    }, 20_000);

    it('keeps the refusal on screen through the reload that follows it', () => {
        const page = fixture.componentInstance;
        page.changeRole(LIST.users[0], 'USER');

        http.expectOne((call) => call.method === 'PATCH' && call.url === '/api/v1/users/1').flush(
            { message: 'The last active administrator cannot be demoted.' },
            { status: 409, statusText: 'Conflict' }
        );

        // The reload is what brings the selector back in line with the database. It must not take
        // the explanation with it — that is the whole reason `reload` has a `preserveError` flag.
        http.expectOne((call) => call.url === '/api/v1/users').flush(LIST);

        expect(page.error()).toContain('last active administrator');
        expect(page.busy()).toBeNull();
    });

    it('does not send a request when the role has not changed', () => {
        // The selector emits on every open, not only on a change. Patching anyway would write an
        // audit entry for a change nobody made.
        fixture.componentInstance.changeRole(LIST.users[1], 'USER');

        http.expectNone(() => true);
    });

    it('sends the state being moved to, not the state it is in', () => {
        fixture.componentInstance.toggleActive(LIST.users[1]);

        const patch = http.expectOne((call) => call.method === 'PATCH' && call.url === '/api/v1/users/2');
        // `is_active: false` for an account that is active. Sending the current value is a
        // deactivation button that does nothing, twice out of two.
        expect(patch.request.body).toEqual({ is_active: false });
        patch.flush({});
        http.expectOne((call) => call.url === '/api/v1/users').flush(LIST);
    });

    it('clears the busy marker whether the change succeeded or was refused', () => {
        const page = fixture.componentInstance;
        page.toggleActive(LIST.users[1]);
        expect(page.busy()).toBe(2);

        http.expectOne((call) => call.method === 'PATCH' && call.url === '/api/v1/users/2').flush(
            { message: 'no' },
            { status: 500, statusText: 'Server Error' }
        );
        http.expectOne((call) => call.url === '/api/v1/users').flush(LIST);

        // A stuck spinner on a row is indistinguishable from a request still in flight, so the
        // operator waits instead of reading the error that is already on screen.
        expect(page.busy()).toBeNull();
    });

    it("reads the account's targets again on opening, rather than starting from empty boxes", () => {
        const page = fixture.componentInstance;
        page.openAccess(LIST.users[1]);

        http.expectOne((call) => call.url === '/api/v1/users/2/targets').flush(
            asSchemaList('UserTargetAssignment', [{ kind: 'repository', id: 7 }])
        );

        // A dialog that opened empty would make every save a total revocation: the administrator
        // ticks what they want to add, sends, and removes everything else without meaning to.
        expect(page.selectedTargets).toEqual(['repository:7']);
    });

    it('sends the set as it stands, empty included, because empty is the revocation', () => {
        const page = fixture.componentInstance;
        page.openAccess(LIST.users[1]);
        http.expectOne((call) => call.url === '/api/v1/users/2/targets').flush(
            asSchemaList('UserTargetAssignment', [{ kind: 'repository', id: 7 }])
        );

        page.selectedTargets = [];
        page.saveAccess();

        const put = http.expectOne((call) => call.method === 'PUT' && call.url === '/api/v1/users/2/targets');
        // **The empty body is a decision.** A guard of "send nothing if nothing is ticked" would
        // make the removal of all access a button with no effect — and that is precisely the
        // operation that matters.
        expect(put.request.body).toEqual([]);
        put.flush([]);

        expect(page.accessVisible()).toBe(false);
    });

    it('splits the box value into kind and identifier, without conflating the two kinds', () => {
        const page = fixture.componentInstance;
        page.openAccess(LIST.users[1]);
        http.expectOne((call) => call.url === '/api/v1/users/2/targets').flush([]);

        page.selectedTargets = ['container:3', 'repository:7'];
        page.saveAccess();

        const put = http.expectOne((call) => call.method === 'PUT' && call.url === '/api/v1/users/2/targets');
        // The identifier is a number: sent as a string, the server no longer matches the row to any
        // target and the assignment vanishes without an error.
        expect(put.request.body).toEqual([
            { kind: 'container', id: 3 },
            { kind: 'repository', id: 7 }
        ]);
        put.flush([]);
    });

    it('keeps the dialog open and says why when the save is refused', () => {
        const page = fixture.componentInstance;
        page.openAccess(LIST.users[1]);
        http.expectOne((call) => call.url === '/api/v1/users/2/targets').flush([]);

        page.selectedTargets = ['repository:7'];
        page.saveAccess();
        http.expectOne((call) => call.method === 'PUT' && call.url === '/api/v1/users/2/targets').flush(
            { message: 'Account not found.' },
            { status: 404, statusText: 'Not Found' }
        );

        // Closed, the dialog would carry the selection away with the message: one would have to
        // tick everything again in order to read the reason for a refusal.
        expect(page.accessVisible()).toBe(true);
        expect(page.formError()).toContain('Account not found.');
    });

    it('denounces itself when the setting makes every assignment pointless', async () => {
        // **The setting silently cancels the screen.** In "everyone" mode, every signed-in account
        // sees the whole estate: ticking targets here restricts nobody, and a screen that did not
        // say so would read as a failure the day somebody checks.
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Users],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        const wide = TestBed.createComponent(Users);
        const calls = TestBed.inject(HttpTestingController);
        wide.detectChanges();
        calls.expectOne((call) => call.url === '/api/v1/users').flush(LIST);
        calls.expectOne((call) => call.url === '/api/v1/api-keys/targets').flush(TARGETS);
        calls
            .expectOne((call) => call.url === '/api/v1/settings')
            .flush(
                asSchema('Catalog', {
                    settings: [
                        {
                            key: 'target_visibility',
                            value: 'everyone',
                            configured: true,
                            governor_only: false,
                            administrator_only: false
                        }
                    ]
                })
            );

        expect(wide.componentInstance.restrictionsInactive()).toBe(true);
    });

    it('says a globally scoped role ignores these boxes', () => {
        const page = fixture.componentInstance;

        page.openAccess(LIST.users[1]);
        http.expectOne((call) => call.url === '/api/v1/users/2/targets').flush([]);
        expect(page.accessUnrestricted(), 'un compte ordinaire est bien restreint').toBe(false);

        page.openAccess({ ...LIST.users[1], role: 'AUDITOR' });
        http.expectOne((call) => call.url === '/api/v1/users/2/targets').flush([]);
        // The auditor sees the whole estate with no assignment — that is the counterpart of their
        // right to read governance, and the screen must say so rather than suggest otherwise.
        expect(page.accessUnrestricted()).toBe(true);
    });
});
