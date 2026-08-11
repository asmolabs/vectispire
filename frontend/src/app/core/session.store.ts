import { Injectable, computed, signal } from '@angular/core';

/** Le serveur les écrit en majuscules (`user.entity.ts`). */
export const ADMIN_ROLES: readonly string[] = ['SUPERUSER', 'ADMIN'];
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

    /**
     * Le vocabulaire des rôles administrateurs, **défini une seule fois**.
     *
     * Il vivait dans le menu, et l'écran des dépôts en avait recopié une variante
     * comparant à `'admin'` en minuscules — donc toujours fausse. Une comparaison de
     * rôle dupliquée est un contrôle d'accès dupliqué : elle divergera, et la divergence
     * se lit soit comme un bouton absent, soit comme un bouton qui rend 403.
     */
    readonly isAdmin = computed(() => ADMIN_ROLES.includes(this.role()));
    /** Le compte doit changer son mot de passe avant d'accéder au reste. */
    readonly mustChangePassword = computed(() => this.user()?.mustChangePassword ?? false);

    /** Après un changement réussi : l'obligation tombe sans qu'il faille se reconnecter,
     *  la session courante ayant délibérément survécu côté serveur. */
    clearMustChangePassword(): void {
        const user = this.user();
        if (user) this.user.set({ ...user, mustChangePassword: false });
    }

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
