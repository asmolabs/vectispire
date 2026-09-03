import { DestroyRef, Signal, effect, inject } from '@angular/core';

/** Les statuts de scan qui n'ont pas fini de bouger. Tout le reste est réglé. */
export const UNSETTLED_SCAN_STATUSES: readonly string[] = ['pending', 'scanning'];

/** True dès qu'un des scans passés n'a pas fini. */
export function anyScanRunning(scans: readonly ({ status?: string } | null | undefined)[]): boolean {
    return scans.some((s) => !!s && UNSETTLED_SCAN_STATUSES.includes((s.status ?? '').toLowerCase()));
}

/**
 * Rafraîchit un écran <b>tant que quelque chose bouge</b>, et se tait dès que c'est fini.
 *
 * <p><b>Pourquoi pas un flux SSE.</b> Le jeton de session vit en mémoire et non dans un cookie —
 * un choix délibéré de {@code SessionStore} — or {@code EventSource} ne sait pas poser d'en-tête
 * {@code Authorization} : il faudrait le porteur dans l'URL, donc dans les journaux d'accès et les
 * proxys. S'y ajoutent deux coûts que la pastille de statut ne justifie pas : un flux est épinglé à
 * une instance alors que le plan de contrôle en supporte plusieurs, et il faudrait le filtrer par
 * abonné à travers {@code VisibilityService}, sur une surface que les tests de routes ne voient
 * pas. Ce que l'on regarde change trois fois en dix minutes ; c'est un problème d'attente sur une
 * page, pas de donnée vivante.
 *
 * <p><b>Conditionnel, et c'est tout l'intérêt.</b> L'écran des agents interrogeait le serveur
 * toutes les cinq secondes en permanence — 720 requêtes par heure et par onglet ouvert, sur un parc
 * au repos. Le compteur ne redémarre ici que lorsque {@code active} redevient vrai, donc un parc
 * qui ne fait rien ne coûte rien.
 *
 * <p>À appeler dans un contexte d'injection. Le nettoyage suit la destruction du composant : un
 * intervalle qui survit à son écran continue d'appeler le serveur pour personne.
 *
 * @param active vrai tant qu'il reste quelque chose à attendre
 * @param refresh ce qu'il faut relire ; jamais appelé immédiatement, l'écran vient de charger
 * @param everyMs le pas, généreux par défaut : un scan dure des minutes, pas des millisecondes
 */
export function pollWhile(active: Signal<boolean>, refresh: () => void, everyMs = 5000): void {
    const destroyRef = inject(DestroyRef);
    let handle: ReturnType<typeof setInterval> | null = null;

    const stop = () => {
        if (handle !== null) {
            clearInterval(handle);
            handle = null;
        }
    };

    effect(() => {
        // Lu dans l'effet : c'est ce qui fait redémarrer le compteur quand un scan est relancé.
        if (active()) {
            if (handle === null) {
                handle = setInterval(refresh, everyMs);
            }
        } else {
            stop();
        }
    });

    destroyRef.onDestroy(stop);
}
