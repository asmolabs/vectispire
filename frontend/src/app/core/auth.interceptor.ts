import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, throwError } from 'rxjs';
import { SessionStore } from './session.store';

/** Les appels dont un 401 n'est pas un jugement sur la session. */
const NOT_A_SESSION_VERDICT = ['/api/v1/auth/change-password'];

/**
 * Pose le jeton sur chaque requête, et traite le 401 en un seul endroit.
 *
 * **Un 401 ferme la session et renvoie à la connexion.** Le serveur est seul juge de la
 * validité d'un jeton — il peut l'avoir révoqué, ou la session avoir expiré pour
 * inactivité — et laisser chaque écran deviner produirait autant d'interprétations que
 * d'écrans.
 *
 * Un **403** n'est pas traité ici, délibérément : il signifie « vous êtes connecté mais
 * ce n'est pas pour vous », et déconnecter quelqu'un parce qu'il a cliqué sur un lien
 * d'administration serait une réaction disproportionnée à une erreur de navigation.
 *
 * **Une exception, et une seule** : le changement de mot de passe. Là, un 401 veut dire
 * « le mot de passe actuel est faux », pas « votre session a expiré » — la règle générale
 * déconnectait pour une faute de frappe, ce qui ne se voit qu'en la commettant.
 */
export const authInterceptor: HttpInterceptorFn = (request, next) => {
    const session = inject(SessionStore);
    const router = inject(Router);

    const token = session.bearer();
    const authorized = token ? request.clone({ setHeaders: { Authorization: `Bearer ${token}` } }) : request;

    return next(authorized).pipe(
        catchError((error: HttpErrorResponse) => {
            const aboutTheSession = !NOT_A_SESSION_VERDICT.some((path) => request.url.startsWith(path));
            if (error.status === 401 && aboutTheSession) {
                session.close();
                // `replaceUrl` : la page qui a échoué ne doit pas rester dans
                // l'historique, sinon le bouton « retour » ramène sur un écran vide.
                void router.navigate(['/login'], { replaceUrl: true });
            }
            return throwError(() => error);
        })
    );
};
