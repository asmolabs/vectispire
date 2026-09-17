import { TestBed, ComponentFixture } from '@angular/core/testing';
import { describe, beforeEach, it, expect, vi } from 'vitest';
import { provideRouter, Router } from '@angular/router';
import { HttpClient } from '@angular/common/http';
import { of, throwError, Subject } from 'rxjs';
import { AppTopbar } from './app.topbar';
import { ApiService } from '@/app/core/api.service';
import { SessionStore } from '@/app/core/session.store';
import { I18nService } from '@/app/core/i18n/i18n.service';

/**
 * Le bouton de déconnexion.
 *
 * <p><b>Ce cas existe parce que le bouton n'a jamais rien fait.</b> Il portait son icône, son
 * libellé traduit et aucun gestionnaire : on cliquait, rien ne bougeait, le jeton restait en
 * mémoire et la session restait ouverte côté serveur. Aucune suite ne pouvait le voir — le
 * gabarit affichait bien quelque chose, et c'est tout ce qu'on lui demandait.
 *
 * <p>Ce qui est éprouvé ici n'est donc pas qu'un bouton s'affiche, mais les trois effets qu'il
 * doit produire : <b>le serveur est prévenu</b>, <b>le navigateur oublie</b> et <b>l'écran part
 * ailleurs</b> — y compris quand le serveur ne répond pas, cas où les deux derniers comptent le
 * plus.
 */
describe('la barre du haut', () => {
    let fixture: ComponentFixture<AppTopbar>;
    let session: SessionStore;
    let logout: ReturnType<typeof vi.fn>;
    let router: Router;

    beforeEach(async () => {
        logout = vi.fn().mockReturnValue(of(undefined));

        await TestBed.configureTestingModule({
            imports: [AppTopbar],
            providers: [
                provideRouter([]),
                { provide: HttpClient, useValue: { get: vi.fn().mockReturnValue(of({})) } },
                { provide: ApiService, useValue: { logout, signInMethods: () => of({}) } }
            ]
        }).compileComponents();

        TestBed.inject(I18nService).translations.set({
            topbar: {
                sign_out: 'Sign out',
                password: 'Password',
                account: 'Account',
                appearance: 'Appearance',
                language: 'Language'
            }
        });

        session = TestBed.inject(SessionStore);
        session.open('a-token', { username: 'c.moreau', role: 'USER' } as never);

        router = TestBed.inject(Router);
        vi.spyOn(router, 'navigate').mockResolvedValue(true);

        fixture = TestBed.createComponent(AppTopbar);
        fixture.detectChanges();
    });

    /** Le bouton, trouvé par son libellé comme un utilisateur le trouve. */
    function button(): HTMLButtonElement {
        const match = Array.from(fixture.nativeElement.querySelectorAll('button'))
            .find((element) => (element as HTMLElement).textContent?.includes('Sign out'));
        expect(match, 'aucun bouton ne porte le libellé de déconnexion').toBeTruthy();
        return match as HTMLButtonElement;
    }

    it('prévient le serveur, oublie la session et quitte la page', () => {
        button().click();
        fixture.detectChanges();

        // **Le serveur d'abord.** Sans cet appel, la ligne de session survit à la déconnexion et
        // un onglet resté ouvert ailleurs continue de fonctionner.
        expect(logout).toHaveBeenCalledOnce();
        expect(session.isAuthenticated()).toBe(false);
        expect(router.navigate).toHaveBeenCalledWith(['/login'], { replaceUrl: true });
    });

    it('oublie la session même quand le serveur ne répond pas', () => {
        // Si un échec réseau laissait l'utilisateur connecté dans son navigateur, le bouton
        // mentirait à nouveau — et cette fois seulement de temps en temps, ce qui est pire.
        logout.mockReturnValue(throwError(() => new Error('réseau')));

        button().click();
        fixture.detectChanges();

        expect(session.isAuthenticated()).toBe(false);
        expect(router.navigate).toHaveBeenCalledWith(['/login'], { replaceUrl: true });
    });

    it('ne révoque pas deux fois quand on clique deux fois', () => {
        // Le bouton se désactive le temps de l'aller-retour, mais la garde est dans la méthode :
        // un second clic parti avant le rendu enverrait sinon une seconde révocation, et la
        // seconde échouerait sur une session que la première vient de fermer.
        const pending = new Subject<void>();
        logout.mockReturnValue(pending);

        fixture.componentInstance.signOut();
        fixture.componentInstance.signOut();
        fixture.detectChanges();

        expect(logout).toHaveBeenCalledOnce();
        expect(button().disabled).toBe(true);

        pending.next();
        pending.complete();
        expect(session.isAuthenticated()).toBe(false);
    });

    /**
     * **Le nom accessible, et non le texte du DOM.**
     *
     * <p>La feuille de style masque sans condition le libellé de ces boutons
     * (`.layout-topbar-action span { display: none }`), si bien qu'ils n'avaient aucun nom : une
     * aide à la lecture d'écran en annonçait trois, indistincts, dont celui qui ferme la session.
     *
     * <p>Rien ne le disait, et ce fichier est une raison. Il cherche le bouton par `textContent`,
     * que jsdom expose parce qu'il n'applique aucune feuille de style — le test lisait un DOM que
     * personne ne voit. Le navigateur, lui, l'a dit : la suite Playwright attendait cent vingt
     * secondes un bouton nommé « Sign out », trois fois de suite, depuis le 15 septembre. Cette
     * assertion-ci porte sur ce que les deux regardent.
     */
    it('nomme ses trois boutons pour autre chose que le DOM', () => {
        const buttons: HTMLButtonElement[] = Array.from(
            (fixture.nativeElement as HTMLElement).querySelectorAll('.layout-topbar-menu button')
        );
        const named = buttons.map((element) => element.getAttribute('aria-label'));

        expect(named).toEqual(['Account', 'Password', 'Sign out']);
    });
});
