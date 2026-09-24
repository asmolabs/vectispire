import { Component, inject, signal } from '@angular/core';
import { Router, RouterModule } from '@angular/router';
import { CommonModule } from '@angular/common';
import { StyleClassModule } from '@openng/optimus-ui/styleclass';
import { AppConfigurator } from './app.configurator';
import { LayoutService } from '@/app/layout/service/layout.service';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { BrandingService } from '@/app/core/branding.service';
import { AuthApi } from '@/app/core/api/auth.api';
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
                        aria-label on all three, because the visible label does not exist. The
                        stylesheet unconditionally hides the text of these buttons
                        (.layout-topbar-action span { display: none }): they therefore have no
                        accessible name, and a screen reader announces three of them without telling
                        them apart — including the one that ends the session. The neighbouring
                        buttons on this same bar already carry one; these had lost it in the move
                        from a hard-coded label to the translated template. The span stays: it is
                        what the stylesheet will show the day it stops hiding it, and the two say
                        the same thing since they read the same key.
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

    private readonly authApi = inject(AuthApi);
    private readonly session = inject(SessionStore);
    private readonly router = inject(Router);

    /** For the duration of the round trip, so a second click does not open a second revocation. */
    readonly signingOut = signal(false);

    /**
     * Ending the session, for real.
     *
     * <p><b>This button never did anything.</b> It carried the icon, the translated label and no
     * handler: you clicked, the page did not move, the token stayed in memory and the session
     * stayed open on the server. That is the worst case for a security control — absent is visible,
     * inert is not — and on a shared workstation, the next person only had to go back.
     *
     * <p><b>The local session closes whatever happens, even if the server did not answer.</b> The
     * order matters: if a network failure left the user signed in in their browser, the button
     * would lie again, and this time only occasionally. The token is in memory — closing it here
     * makes it unusable for this browser; what can survive a broken network is the session row on
     * the server, which its expiry eventually carries away.
     *
     * <p>`replaceUrl`, as in the interceptor: the page being left must not stay in the history,
     * without which the "back" button brings back an empty screen.
     */
    signOut(): void {
        if (this.signingOut()) return;
        this.signingOut.set(true);

        this.authApi.logout().subscribe({
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
