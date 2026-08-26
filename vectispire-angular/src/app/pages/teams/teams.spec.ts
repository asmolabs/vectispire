import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { Teams } from './teams';

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

    const TEAM = { id: 4, name: 'platform', description: null, memberCount: 1, targetCount: 2, notified: false };

    const ACCOUNTS = {
        users: [
            { id: 1, username: 'admin', email: null, displayName: 'The Administrator', role: 'ADMINISTRATOR', isActive: true, mustChangePassword: false, createdAt: '2026-01-01T00:00:00Z', activeSessions: 1 },
            { id: 2, username: 'reader', email: null, displayName: null, role: 'READER', isActive: true, mustChangePassword: false, createdAt: '2026-01-01T00:00:00Z', activeSessions: 0 }
        ]
    };

    const TARGETS = {
        repositories: [{ id: 7, label: 'ours' }],
        containers: [{ id: 3, label: 'registry.invalid/app:1.0' }]
    };

    function settleBoot(accounts: object = ACCOUNTS): void {
        http.expectOne((call) => call.url === '/api/v1/teams').flush([TEAM]);
        http.expectOne((call) => call.url === '/api/v1/users').flush(accounts);
        http.expectOne((call) => call.url === '/api/v1/api-keys/targets').flush(TARGETS);
    }

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Teams],
            providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

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
        http.expectOne((call) => call.url === '/api/v1/teams/4/targets').flush([
            { kind: 'repository', id: 7 },
            { kind: 'container', id: 3 }
        ]);

        expect(fixture.componentInstance.selectedMembers).toEqual([2]);
        // Held as `kind:id` strings because that is what the picker's option values are.
        expect(fixture.componentInstance.selectedTargets).toEqual(['repository:7', 'container:3']);
    });

    it('parses the identifiers back into numbers when saving', () => {
        settleBoot();
        const page = fixture.componentInstance;
        page.openAccess(TEAM);
        http.expectOne((call) => call.url === '/api/v1/teams/4/members').flush([]);
        http.expectOne((call) => call.url === '/api/v1/teams/4/targets').flush([]);

        page.selectedMembers = [2];
        page.selectedTargets = ['repository:7', 'container:3'];
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

        page.selectedMembers = [2];
        page.selectedTargets = ['repository:7'];
        page.saveAccess();

        http.expectOne((call) => call.method === 'PUT' && call.url === '/api/v1/teams/4/members').flush([2]);
        http.expectOne((call) => call.method === 'PUT' && call.url === '/api/v1/teams/4/targets')
            .flush({ message: 'nope' }, { status: 500, statusText: 'Server Error' });

        // The dialog stays open and names the half that applied. "Could not save" would leave an
        // administrator to guess whether the membership change took effect — and it did.
        expect(page.accessVisible()).toBe(true);
        expect(page.formError()).toContain('membership was saved');
        expect(page.saving()).toBe(false);
    });
});
