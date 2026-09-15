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

    const TARGETS = {
        repositories: [{ id: 7, label: 'portail-client' }],
        containers: [{ id: 3, label: 'registry/service:1.4' }]
    };

    /** Le mode restreint, qui est le défaut d'une installation neuve. */
    const SETTINGS = { settings: [{ key: 'target_visibility', value: 'assigned' }] };

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

        // La liste des cibles et le mode de visibilité, demandés par le constructeur pour la
        // boîte de visibilité. Vidés ici pour que les cas qui n'en parlent pas restent lisibles —
        // et le mode par défaut est le mode restreint, celui où les affectations comptent.
        http.expectOne((call) => call.url === '/api/v1/api-keys/targets').flush(TARGETS);
        http.expectOne((call) => call.url === '/api/v1/settings').flush(SETTINGS);
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

    it("relit les cibles du compte à l'ouverture, plutôt que de partir d'une case vide", () => {
        const page = fixture.componentInstance;
        page.openAccess(LIST.users[1]);

        http.expectOne((call) => call.url === '/api/v1/users/2/targets')
            .flush([{ kind: 'repository', id: 7 }]);

        // Une boîte qui s'ouvrirait vide ferait de chaque enregistrement une révocation totale :
        // l'administrateur coche ce qu'il veut ajouter, envoie, et retire tout le reste sans
        // l'avoir voulu.
        expect(page.selectedTargets).toEqual(['repository:7']);
    });

    it("envoie l'ensemble tel quel, vide compris, parce que le vide est la révocation", () => {
        const page = fixture.componentInstance;
        page.openAccess(LIST.users[1]);
        http.expectOne((call) => call.url === '/api/v1/users/2/targets')
            .flush([{ kind: 'repository', id: 7 }]);

        page.selectedTargets = [];
        page.saveAccess();

        const put = http.expectOne((call) => call.method === 'PUT' && call.url === '/api/v1/users/2/targets');
        // **Le corps vide est une décision.** Une garde « ne rien envoyer si rien n'est coché »
        // ferait du retrait de tout accès un bouton sans effet — l'opération qui compte est
        // précisément celle-là.
        expect(put.request.body).toEqual([]);
        put.flush([]);

        expect(page.accessVisible()).toBe(false);
    });

    it('découpe la valeur de la case en genre et identifiant, sans confondre les deux genres', () => {
        const page = fixture.componentInstance;
        page.openAccess(LIST.users[1]);
        http.expectOne((call) => call.url === '/api/v1/users/2/targets').flush([]);

        page.selectedTargets = ['container:3', 'repository:7'];
        page.saveAccess();

        const put = http.expectOne((call) => call.method === 'PUT' && call.url === '/api/v1/users/2/targets');
        // L'identifiant est un nombre : envoyé en chaîne, le serveur ne rapproche plus la ligne
        // d'aucune cible et l'affectation disparaît sans erreur.
        expect(put.request.body).toEqual([{ kind: 'container', id: 3 }, { kind: 'repository', id: 7 }]);
        put.flush([]);
    });

    it("garde la boîte ouverte et dit pourquoi quand l'enregistrement est refusé", () => {
        const page = fixture.componentInstance;
        page.openAccess(LIST.users[1]);
        http.expectOne((call) => call.url === '/api/v1/users/2/targets').flush([]);

        page.selectedTargets = ['repository:7'];
        page.saveAccess();
        http.expectOne((call) => call.method === 'PUT' && call.url === '/api/v1/users/2/targets')
            .flush({ message: 'Account not found.' }, { status: 404, statusText: 'Not Found' });

        // Fermée, la boîte emporterait la sélection avec le message : il faudrait tout recocher
        // pour lire la raison d'un refus.
        expect(page.accessVisible()).toBe(true);
        expect(page.formError()).toContain('Account not found.');
    });

    it('se dénonce quand le réglage rend toute affectation sans effet', async () => {
        // **Le réglage annule silencieusement l'écran.** En mode « tout le monde », chaque compte
        // connecté voit tout le parc : cocher des cibles ici ne restreint personne, et un écran
        // qui ne le dirait pas se lirait comme une panne le jour où quelqu'un vérifie.
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Users],
            providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        const wide = TestBed.createComponent(Users);
        const calls = TestBed.inject(HttpTestingController);
        wide.detectChanges();
        calls.expectOne((call) => call.url === '/api/v1/users').flush(LIST);
        calls.expectOne((call) => call.url === '/api/v1/api-keys/targets').flush(TARGETS);
        calls.expectOne((call) => call.url === '/api/v1/settings')
            .flush({ settings: [{ key: 'target_visibility', value: 'everyone' }] });

        expect(wide.componentInstance.restrictionsInactive()).toBe(true);
    });

    it('dit qu\'un rôle à portée globale ignore ces cases', () => {
        const page = fixture.componentInstance;

        page.openAccess(LIST.users[1]);
        http.expectOne((call) => call.url === '/api/v1/users/2/targets').flush([]);
        expect(page.accessUnrestricted(), 'un compte ordinaire est bien restreint').toBe(false);

        page.openAccess({ ...LIST.users[1], role: 'AUDITOR' });
        http.expectOne((call) => call.url === '/api/v1/users/2/targets').flush([]);
        // L'auditeur voit tout le parc sans affectation — c'est la contrepartie de son droit de
        // lire la gouvernance, et l'écran doit le dire plutôt que de laisser croire au contraire.
        expect(page.accessUnrestricted()).toBe(true);
    });
});
