import { Component, inject, signal } from '@angular/core';
import { Router, RouterModule } from '@angular/router';
import { CommonModule } from '@angular/common';
import { StyleClassModule } from '@openng/optimus-ui/styleclass';
import { AppConfigurator } from './app.configurator';
import { LayoutService } from '@/app/layout/service/layout.service';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { BrandingService } from '@/app/core/branding.service';
import { ApiService } from '@/app/core/api.service';
import { SessionStore } from '@/app/core/session.store';
import { TranslatePipe } from '@/app/core/i18n/translate.pipe';

@Component({
    selector: 'app-topbar',
    standalone: true,
    imports: [RouterModule, CommonModule, StyleClassModule, AppConfigurator, TranslatePipe],
    template: ` <div class="layout-topbar">
        <div class="layout-topbar-logo-container">
            <button class="layout-menu-button layout-topbar-action" (click)="layoutService.onMenuToggle()">
                <i class="pi pi-bars"></i>
            </button>
            <a class="layout-topbar-logo" routerLink="/dashboard">
                <!-- "Vectispire": Vectis (security lock/lever) + Spire (ASPM watchtower & posture elevation). -->
                <svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
                    <path d="M20 2.5 4.5 8.2v11.3c0 9.1 6.3 15.9 15.5 18 9.2-2.1 15.5-8.9 15.5-18V8.2L20 2.5Z" stroke="var(--primary-color)" stroke-width="2.6" stroke-linejoin="round" fill="none" />
                    <path d="M11 19.4c2.4-3.6 5.4-5.4 9-5.4s6.6 1.8 9 5.4c-2.4 3.6-5.4 5.4-9 5.4s-6.6-1.8-9-5.4Z" stroke="var(--primary-color)" stroke-width="2.2" stroke-linejoin="round" fill="none" />
                    <circle cx="20" cy="19.4" r="2.6" fill="var(--primary-color)" />
                </svg>
                <span>{{ branding.brandName().toUpperCase() }}</span>
            </a>
        </div>

        <div class="layout-topbar-actions">
            <div class="layout-config-menu">
                <!-- Language Selector Toggle -->
                <button
                    type="button"
                    class="layout-topbar-action font-semibold text-xs uppercase"
                    (click)="toggleLanguage()"
                    [attr.aria-label]="'topbar.language' | translate"
                    [title]="'topbar.language' | translate"
                >
                    <span>{{ i18n.currentLang() === 'en' ? 'FR' : 'EN' }}</span>
                </button>

                <button
                    type="button"
                    class="layout-topbar-action"
                    (click)="toggleDarkMode()"
                    [attr.aria-label]="layoutService.isDarkTheme() ? ('topbar.switch_light' | translate) : ('topbar.switch_dark' | translate)"
                >
                    <i [ngClass]="{ 'pi ': true, 'pi-moon': layoutService.isDarkTheme(), 'pi-sun': !layoutService.isDarkTheme() }"></i>
                </button>
                <div class="relative">
                    <button
                        class="layout-topbar-action layout-topbar-action-highlight"
                        pStyleClass="@next"
                        enterFromClass="hidden"
                        enterActiveClass="animate-scalein"
                        leaveToClass="hidden"
                        leaveActiveClass="animate-fadeout"
                        [hideOnOutsideClick]="true"
                        [attr.aria-label]="'topbar.appearance' | translate"
                    >
                        <i class="pi pi-palette"></i>
                    </button>
                    <app-configurator />
                </div>
            </div>

            <button
                class="layout-topbar-menu-button layout-topbar-action"
                pStyleClass="@next"
                enterFromClass="hidden"
                enterActiveClass="animate-scalein"
                leaveToClass="hidden"
                leaveActiveClass="animate-fadeout"
                [hideOnOutsideClick]="true"
            >
                <i class="pi pi-ellipsis-v"></i>
            </button>

            <!--
                Sakai's user menu offered Calendar / Messages / Profile, three screens
                Vectispire does not have. Only the two real actions remain; the displayed
                name and role will come from the session service.
            -->
            <div class="layout-topbar-menu hidden lg:block">
                <div class="layout-topbar-menu-content">
                    <!--
                        aria-label sur les trois, parce que le libellé visible n'existe pas.
                        La feuille de style masque sans condition le texte de ces boutons
                        (.layout-topbar-action span { display: none }) : ils n'ont donc aucun nom
                        accessible, et une aide à la lecture d'écran en annonce trois sans les
                        distinguer — dont celui qui ferme la session. Les boutons voisins de cette
                        même barre en portent déjà un ; ceux-ci l'avaient perdu en passant du
                        libellé en dur au gabarit traduit. Le span reste : c'est lui que la feuille
                        de style montrera le jour où elle cessera de le cacher, et les deux disent
                        la même chose puisqu'ils lisent la même clé.
                    -->
                    <button type="button" class="layout-topbar-action" routerLink="/account"
                            [attr.aria-label]="'topbar.account' | translate">
                        <i class="pi pi-user"></i>
                        <span>{{ 'topbar.account' | translate }}</span>
                    </button>
                    <button type="button" class="layout-topbar-action" routerLink="/change-password"
                            [attr.aria-label]="'topbar.password' | translate">
                        <i class="pi pi-key"></i>
                        <span>{{ 'topbar.password' | translate }}</span>
                    </button>
                    <button type="button" class="layout-topbar-action"
                            [attr.aria-label]="'topbar.sign_out' | translate"
                            [disabled]="signingOut()" (click)="signOut()">
                        <i class="pi pi-sign-out"></i>
                        <span>{{ 'topbar.sign_out' | translate }}</span>
                    </button>
                </div>
            </div>
        </div>
    </div>`
})
export class AppTopbar {
    layoutService = inject(LayoutService);
    i18n = inject(I18nService);
    branding = inject(BrandingService);

    private readonly api = inject(ApiService);
    private readonly session = inject(SessionStore);
    private readonly router = inject(Router);

    /** Le temps de l'aller-retour, pour qu'un second clic n'ouvre pas une seconde révocation. */
    readonly signingOut = signal(false);

    /**
     * Fermer la session, pour de vrai.
     *
     * <p><b>Ce bouton n'a jamais rien fait.</b> Il portait l'icône, le libellé traduit et aucun
     * gestionnaire : on cliquait, la page ne bougeait pas, le jeton restait en mémoire et la
     * session restait ouverte côté serveur. C'est le pire cas de figure pour un contrôle de
     * sécurité — absent est visible, inerte ne l'est pas — et sur un poste partagé, le suivant
     * n'avait qu'à revenir en arrière.
     *
     * <p><b>La session locale se ferme quoi qu'il arrive, même si le serveur n'a pas répondu.</b>
     * L'ordre importe : si l'échec réseau laissait l'utilisateur connecté dans son navigateur, le
     * bouton mentirait à nouveau, et cette fois seulement de temps en temps. Le jeton est en
     * mémoire — le fermer ici le rend inutilisable pour ce navigateur ; ce qui peut survivre à un
     * réseau coupé est la ligne de session côté serveur, que son expiration finit par emporter.
     *
     * <p>`replaceUrl`, comme dans l'intercepteur : la page quittée ne doit pas rester dans
     * l'historique, sans quoi le bouton « précédent » ramène un écran vide.
     */
    signOut(): void {
        if (this.signingOut()) return;
        this.signingOut.set(true);

        this.api.logout().subscribe({
            next: () => this.forget(),
            error: () => this.forget()
        });
    }

    private forget(): void {
        this.session.close();
        this.signingOut.set(false);
        void this.router.navigate(['/login'], { replaceUrl: true });
    }

    toggleDarkMode() {
        this.layoutService.layoutConfig.update((state) => ({
            ...state,
            darkTheme: !state.darkTheme
        }));
    }

    toggleLanguage() {
        const next = this.i18n.currentLang() === 'en' ? 'fr' : 'en';
        this.i18n.setLanguage(next);
    }
}
