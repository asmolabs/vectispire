import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { Users } from './users';

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

    const account = (id: number, username: string, role: string, isActive = true) => ({
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

    const LIST = { users: [account(1, 'admin', 'ADMINISTRATOR'), account(2, 'reader', 'READER')], currentUserId: 1 };

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Users],
            providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        fixture = TestBed.createComponent(Users);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        http.expectOne((call) => call.url === '/api/v1/users').flush(LIST);
    }, 20_000);

    it('keeps the refusal on screen through the reload that follows it', () => {
        const page = fixture.componentInstance;
        page.changeRole(LIST.users[0], 'READER');

        http.expectOne((call) => call.method === 'PATCH' && call.url === '/api/v1/users/1')
            .flush({ message: 'The last active administrator cannot be demoted.' }, { status: 409, statusText: 'Conflict' });

        // The reload is what brings the selector back in line with the database. It must not take
        // the explanation with it — that is the whole reason `reload` has a `preserveError` flag.
        http.expectOne((call) => call.url === '/api/v1/users').flush(LIST);

        expect(page.error()).toContain('last active administrator');
        expect(page.busy()).toBeNull();
    });

    it('does not send a request when the role has not changed', () => {
        // The selector emits on every open, not only on a change. Patching anyway would write an
        // audit entry for a change nobody made.
        fixture.componentInstance.changeRole(LIST.users[1], 'READER');

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

        http.expectOne((call) => call.method === 'PATCH' && call.url === '/api/v1/users/2')
            .flush({ message: 'no' }, { status: 500, statusText: 'Server Error' });
        http.expectOne((call) => call.url === '/api/v1/users').flush(LIST);

        // A stuck spinner on a row is indistinguishable from a request still in flight, so the
        // operator waits instead of reading the error that is already on screen.
        expect(page.busy()).toBeNull();
    });
});
