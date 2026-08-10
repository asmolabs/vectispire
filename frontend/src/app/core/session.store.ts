import { Injectable, computed, signal } from '@angular/core';
import { AuthenticatedUser } from './api.models';

/**
 * La session, côté navigateur.
 *
 * **Le jeton vit en mémoire, pas en `localStorage`.** C'est un écart délibéré avec la
 * version Reflex, qui y gardait son jeton de client : ce qui est en `localStorage` est
 * lisible par tout script de la page, donc exfiltrable par la moindre faille XSS, et
 * survit indéfiniment à la fermeture de l'onglet.
 *
 * Le prix est réel et assumé : recharger la page déconnecte. Le remède propre est un
 * cookie `HttpOnly` posé par le serveur, que le navigateur envoie sans que le
 * JavaScript puisse le lire — à faire quand le déploiement sera fixé, l'API acceptant
 * déjà un jeton porteur.
 */
@Injectable({ providedIn: 'root' })
export class SessionStore {
    private readonly token = signal<string | null>(null);
    readonly user = signal<AuthenticatedUser | null>(null);

    readonly isAuthenticated = computed(() => this.token() !== null);
    readonly role = computed(() => this.user()?.role ?? '');
    /** Le compte doit changer son mot de passe avant d'accéder au reste. */
    readonly mustChangePassword = computed(() => this.user()?.mustChangePassword ?? false);

    open(token: string, user: AuthenticatedUser): void {
        this.token.set(token);
        this.user.set(user);
    }

    close(): void {
        this.token.set(null);
        this.user.set(null);
    }

    /** Lu par l'intercepteur, et par lui seul. */
    bearer(): string | null {
        return this.token();
    }
}
