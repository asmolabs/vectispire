/**
 * Les règles d'une décision de triage — validation et échéance.
 *
 * Dans le domaine, et donc sans base : ce sont des règles de vocabulaire et
 * d'arithmétique de dates, elles se testent exhaustivement. Le service applique
 * ensuite le résultat à une ligne.
 *
 * Le vocabulaire est déclaré **ici** et non repris des entités : la règle de couches
 * interdit au domaine de connaître la persistance, et c'est le bon sens de la
 * dépendance — le vocabulaire VEX existe indépendamment de la table qui le stocke.
 */

export const TRIAGE_UNDER_REVIEW = 'under_review';
export const TRIAGE_AFFECTED = 'affected';
export const TRIAGE_NOT_AFFECTED = 'not_affected';
export const TRIAGE_FIXED = 'fixed';

export class InvalidTriageError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'InvalidTriageError';
    }
}

export interface TriageRequest {
    status: string;
    actor: string;
    justification?: string | null;
    comment?: string | null;
    /**
     * Une date de révision, **proposée et non imposée** : décider qu'un composant
     * n'est simplement pas présent n'a pas besoin d'être réexaminé à échéance, alors
     * que « pas atteignable dans notre configuration » en a grand besoin — et seule
     * la personne qui décide sait laquelle des deux elle vient d'enregistrer.
     */
    expiresInDays?: number | null;
}

export interface TriageDecision {
    status: string;
    justification: string | null;
    comment: string | null;
    triagedBy: string;
    triagedAt: string;
    expiresAt: string | null;
}

/**
 * Valide une demande de triage et calcule ce qu'il faut écrire.
 *
 * Lève `InvalidTriageError` sur tout ce qui est invalide, avec un message destiné à
 * être montré tel quel : c'est la personne qui triait qui a besoin de savoir pourquoi
 * sa décision est refusée.
 *
 * @param now L'instant de la décision, au format `datetime.isoformat()`.
 */
export function decideTriage(request: TriageRequest, now: string): TriageDecision {
    if (!VALID_TRIAGE_STATUSES.includes(request.status)) {
        throw new InvalidTriageError(`Statut de triage invalide : ${request.status}`);
    }

    const justification = (request.justification ?? '').trim() || null;
    if (justification && !VEX_JUSTIFICATIONS.includes(justification)) {
        throw new InvalidTriageError(`Justification VEX inconnue : ${justification}`);
    }
    // VEX **exige** une justification pour « not_affected » : sans elle, la
    // déclaration ne porte aucune information, et un document VEX exporté la
    // contenant serait invalide.
    if (request.status === TRIAGE_NOT_AFFECTED && !justification) {
        throw new InvalidTriageError('Une justification est requise pour le statut « non affecté » (exigence VEX).');
    }

    return {
        status: request.status,
        justification,
        comment: (request.comment ?? '').trim() || null,
        triagedBy: request.actor,
        triagedAt: now,
        expiresAt: expiryFrom(request.status, request.expiresInDays ?? null, now)
    };
}

/**
 * Une date de révision, ou `null`.
 *
 * Un retour à `under_review` efface toute échéance : le problème est déjà dans la
 * file, et une date pour l'y ramener ne déclencherait sur rien.
 */
export function expiryFrom(status: string, expiresInDays: number | null, now: string): string | null {
    if (status === TRIAGE_UNDER_REVIEW || expiresInDays === null || expiresInDays === undefined) return null;

    // `null` veut dire « pas de date de révision » ; zéro ou un nombre négatif veut
    // dire que l'appelant s'est trompé dans son calcul, et le traiter en silence
    // comme « jamais » masquerait l'erreur.
    const days = Math.trunc(expiresInDays);
    if (days <= 0) throw new InvalidTriageError("Le délai de révision doit être d'au moins un jour.");

    return addDays(now, days);
}

/**
 * Une décision est-elle passée sa date de révision ?
 *
 * Une suppression est un énoncé sur un contexte, et les contextes changent. Sans
 * cette expiration, un `not_affected` posé en janvier restait autoritaire en décembre
 * — dans le document VEX remis à un client autant que sur le tableau de bord. C'est
 * ainsi que pourrissent les suppressions VEX.
 */
export function isTriageExpired(issue: { triageStatus: string | null; triageExpiresAt: string | null }, now: string): boolean {
    if (!issue.triageExpiresAt || issue.triageStatus === TRIAGE_UNDER_REVIEW) return false;
    // Comparaison lexicographique : deux isoformat de même forme s'ordonnent comme
    // les instants qu'ils représentent, et cela évite un aller-retour par `Date` qui
    // perdrait la microseconde.
    return now >= issue.triageExpiresAt;
}

/**
 * Ce qu'une expiration change sur un problème — et surtout ce qu'elle **ne change
 * pas**.
 *
 * La justification et le commentaire sont *conservés*. La décision avait une raison,
 * et qui la réexamine a besoin de la voir : effacer le texte transformerait un
 * réexamen programmé en enquête repartie de zéro, ce qui est la façon dont une date de
 * révision devient une chose que les gens cessent de renseigner.
 *
 * `triagedBy` et `triagedAt` sont gardés pour la même raison, et parce qu'ils sont la
 * trace de qui a dit quoi : les écraser effacerait une preuve.
 */
export function expireTriage<T extends { triageStatus: string | null; triageExpiresAt: string | null }>(issue: T): T {
    issue.triageStatus = TRIAGE_UNDER_REVIEW;
    issue.triageExpiresAt = null;
    return issue;
}

function addDays(isoformat: string, days: number): string {
    const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{1,6})?$/.exec(isoformat);
    if (!match) throw new InvalidTriageError(`Horodatage illisible : ${JSON.stringify(isoformat)}`);

    const [, year, month, day, hour, minute, second, fraction] = match;
    const shifted = new Date(Date.UTC(Number(year), Number(month) - 1, Number(day), Number(hour), Number(minute), Number(second)));
    shifted.setUTCDate(shifted.getUTCDate() + days);

    const pad = (value: number) => String(value).padStart(2, '0');
    const base =
        `${shifted.getUTCFullYear()}-${pad(shifted.getUTCMonth() + 1)}-${pad(shifted.getUTCDate())}` +
        `T${pad(shifted.getUTCHours())}:${pad(shifted.getUTCMinutes())}:${pad(shifted.getUTCSeconds())}`;
    // La fraction est reportée telle quelle : ajouter des jours ne la touche pas, et
    // la reconstruire risquerait de la reformater autrement que Python.
    return fraction ? `${base}${fraction}` : base;
}

export const VALID_TRIAGE_STATUSES: readonly string[] = [TRIAGE_UNDER_REVIEW, TRIAGE_AFFECTED, TRIAGE_NOT_AFFECTED, TRIAGE_FIXED];

/**
 * Les justifications VEX d'une déclaration `not_affected`, selon le vocabulaire
 * OpenVEX / CSAF.
 *
 * Gardées comme liste canonique pour qu'un document VEX puisse être produit depuis ces
 * lignes sans re-traduire du texte libre. C'est toute la raison pour laquelle le
 * triage est stocké dans le vocabulaire de la norme.
 */
export const VEX_JUSTIFICATIONS: readonly string[] = [
    'component_not_present',
    'vulnerable_code_not_present',
    'vulnerable_code_not_in_execute_path',
    'vulnerable_code_cannot_be_controlled_by_adversary',
    'inline_mitigations_already_exist'
];
