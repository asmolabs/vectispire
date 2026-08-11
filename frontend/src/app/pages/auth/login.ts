import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { PasswordModule } from '@openng/optimus-ui/password';
import { ApiService } from '@/app/core/api.service';
import { SessionStore } from '@/app/core/session.store';

/**
 * L'écran de connexion.
 *
 * **Aucun identifiant par défaut n'est affiché**, contrairement à ce que faisait la
 * version Reflex. Le compte de provisionnement porte `mustChangePassword`, ce qui est
 * la façon correcte de dire « changez votre mot de passe » sans écrire lequel.
 *
 * Le message d'erreur ne distingue pas « compte inconnu » de « mot de passe faux » —
 * l'API ne le distingue pas non plus, et les séparer donnerait à qui sonde la liste
 * des comptes existants. Le blocage par le limiteur, lui, est annoncé : c'est une
 * information dont la personne a besoin pour savoir qu'attendre suffit.
 */
@Component({
    selector: 'zs-login',
    standalone: true,
    imports: [FormsModule, ButtonModule, InputTextModule, PasswordModule, MessageModule],
    template: `
        <div class="flex items-center justify-center min-h-screen overflow-hidden">
            <div class="flex flex-col items-center justify-center w-full max-w-md">
                <div style="border-radius: 56px; padding: 0.3rem; background: linear-gradient(180deg, var(--primary-color) 10%, rgba(33,150,243,0) 30%)">
                    <div class="w-full bg-surface-0 dark:bg-surface-900 py-16 px-8 sm:px-16" style="border-radius: 53px">
                        <div class="text-center mb-8">
                            <div class="text-surface-900 dark:text-surface-0 text-3xl font-medium mb-2">Zanshin</div>
                            <span class="text-muted-color font-medium">Analyse de sécurité applicative</span>
                        </div>

                        <form (ngSubmit)="submit()">
                            <label for="username" class="block text-surface-900 dark:text-surface-0 text-xl font-medium mb-2">Identifiant</label>
                            <input pInputText id="username" name="username" type="text" autocomplete="username" class="w-full mb-6" [(ngModel)]="username" />

                            <label for="password" class="block text-surface-900 dark:text-surface-0 font-medium text-xl mb-2">Mot de passe</label>
                            <!-- Entrée valide explicitement : « p-password » encapsule son champ, et la touche
                                 n'atteignait pas la soumission du formulaire — se connecter au clavier
                                 ne marchait pas, ce qui ne se voit qu'en essayant. -->
                            <p-password id="password" name="password" [(ngModel)]="password" [toggleMask]="true" [feedback]="false"
                                        styleClass="mb-4" [fluid]="true" (keyup.enter)="submit()" />

                            @if (error()) {
                                <p-message severity="error" [text]="error()!" styleClass="w-full mb-4" />
                            }

                            <p-button type="submit" label="Se connecter" styleClass="w-full" [loading]="loading()" />
                        </form>
                    </div>
                </div>
            </div>
        </div>
    `
})
export class Login {
    private readonly api = inject(ApiService);
    private readonly session = inject(SessionStore);
    private readonly router = inject(Router);

    username = '';
    password = '';
    readonly loading = signal(false);
    readonly error = signal<string | null>(null);

    submit(): void {
        if (this.loading()) return;
        this.loading.set(true);
        this.error.set(null);

        this.api.login(this.username, this.password, clientId()).subscribe({
            next: (response) => {
                this.session.open(response.token, response.user);
                // Un compte de provisionnement va d'abord changer son mot de passe : le
                // laisser atteindre le reste viderait le drapeau de son sens.
                void this.router.navigate([response.user.mustChangePassword ? '/change-password' : '/dashboard']);
            },
            error: (response: { status: number; error?: { message?: string; retryAfterSeconds?: number } }) => {
                this.loading.set(false);
                const retryAfter = response.error?.retryAfterSeconds;
                this.error.set(retryAfter ? `Trop de tentatives. Réessayez dans ${Math.ceil(retryAfter / 60)} minute(s).` : 'Identifiants invalides.');
            }
        });
    }
}

/**
 * Identifie ce navigateur pour le second compteur du limiteur.
 *
 * Persisté, parce qu'un identifiant tiré à chaque chargement rendrait ce compteur
 * inopérant — c'est précisément celui qui empêche un attaquant de balayer la liste des
 * comptes depuis un même poste. Il ne s'agit pas d'un secret : le perdre ne donne rien
 * à personne, il rend seulement le limiteur plus indulgent.
 */
function clientId(): string {
    const key = 'zanshin.client';
    let value = localStorage.getItem(key);
    if (!value) {
        value = crypto.randomUUID();
        localStorage.setItem(key, value);
    }
    return value;
}
