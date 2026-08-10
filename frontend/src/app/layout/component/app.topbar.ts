import { Component, inject } from '@angular/core';
import { RouterModule } from '@angular/router';
import { CommonModule } from '@angular/common';
import { StyleClassModule } from '@openng/optimus-ui/styleclass';
import { AppConfigurator } from './app.configurator';
import { LayoutService } from '@/app/layout/service/layout.service';

@Component({
    selector: 'app-topbar',
    standalone: true,
    imports: [RouterModule, CommonModule, StyleClassModule, AppConfigurator],
    template: ` <div class="layout-topbar">
        <div class="layout-topbar-logo-container">
            <button class="layout-menu-button layout-topbar-action" (click)="layoutService.onMenuToggle()">
                <i class="pi pi-bars"></i>
            </button>
            <a class="layout-topbar-logo" routerLink="/dashboard">
                <!-- « Zanshin » : la vigilance qui subsiste après l'action. Un œil
                     ouvert dans un bouclier — un scan n'est pas un état, c'est une
                     surveillance qui continue. -->
                <svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
                    <path d="M20 2.5 4.5 8.2v11.3c0 9.1 6.3 15.9 15.5 18 9.2-2.1 15.5-8.9 15.5-18V8.2L20 2.5Z" stroke="var(--primary-color)" stroke-width="2.6" stroke-linejoin="round" fill="none" />
                    <path d="M11 19.4c2.4-3.6 5.4-5.4 9-5.4s6.6 1.8 9 5.4c-2.4 3.6-5.4 5.4-9 5.4s-6.6-1.8-9-5.4Z" stroke="var(--primary-color)" stroke-width="2.2" stroke-linejoin="round" fill="none" />
                    <circle cx="20" cy="19.4" r="2.6" fill="var(--primary-color)" />
                </svg>
                <span>ZANSHIN</span>
            </a>
        </div>

        <div class="layout-topbar-actions">
            <div class="layout-config-menu">
                <button type="button" class="layout-topbar-action" (click)="toggleDarkMode()" [attr.aria-label]="layoutService.isDarkTheme() ? 'Passer en thème clair' : 'Passer en thème sombre'">
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
                        aria-label="Apparence"
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
                Le menu utilisateur de Sakai proposait Calendar / Messages / Profile,
                trois écrans que Zanshin n'a pas. Ne restent que les deux actions
                réelles ; le nom et le rôle affichés viendront du service de session
                au lot 1.
            -->
            <div class="layout-topbar-menu hidden lg:block">
                <div class="layout-topbar-menu-content">
                    <button type="button" class="layout-topbar-action" routerLink="/change-password">
                        <i class="pi pi-key"></i>
                        <span>Mot de passe</span>
                    </button>
                    <button type="button" class="layout-topbar-action">
                        <i class="pi pi-sign-out"></i>
                        <span>Se déconnecter</span>
                    </button>
                </div>
            </div>
        </div>
    </div>`
})
export class AppTopbar {
    layoutService = inject(LayoutService);

    toggleDarkMode() {
        this.layoutService.layoutConfig.update((state) => ({
            ...state,
            darkTheme: !state.darkTheme
        }));
    }
}
