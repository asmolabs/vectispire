/**
 * Quel agent a le droit d'exécuter quel scan.
 *
 * **La file n'était routée par aucun critère.** N'importe quel agent enregistré réclamait
 * n'importe quel scan, et le premier qui demandait était servi. Un agent posé dans un
 * segment de moindre confiance — parce qu'il doit y atteindre un dépôt, ce qui est
 * précisément la raison d'exister des agents distants — pouvait donc réclamer les scans de
 * tous les autres dépôts, et recevoir leurs clés de déploiement avec.
 *
 * Ni le scellement de bout en bout ni le mode `local` ne referment cela : le premier
 * protège la clé *en chemin* et l'ouvre bien chez le demandeur, le second retire la clé mais
 * laisse l'agent lire le code source. La seule réponse est de dire **où** un scan a le droit
 * d'aller.
 *
 * **Une étiquette, pas une liste d'agents.** Nommer des agents ferait de chaque
 * remplacement de machine une modification de tous les dépôts qu'elle sert ; une étiquette
 * décrit une *capacité* — « atteint le réseau de production », « habilité aux dépôts
 * clients » — et un agent neuf la porte dès son enregistrement.
 *
 * **Fermé par défaut du côté de l'agent, ouvert du côté du scan.** Un scan sans exigence va
 * à n'importe qui : c'est le comportement d'avant, et l'imposer rétroactivement arrêterait
 * toutes les files existantes au premier déploiement. Un agent sans étiquette, lui, ne
 * prend que le travail sans exigence — il ne « correspond pas à tout ».
 */

/** Séparateur des étiquettes d'un agent, tel que l'opérateur les saisit. */
const SEPARATOR = ',';

/**
 * Les étiquettes d'un agent, normalisées.
 *
 * Espaces retirés et casse abaissée : « Production » et « production » saisis à six mois
 * d'intervalle sur deux écrans différents doivent désigner la même chose, sans quoi un scan
 * attendrait indéfiniment un agent qui est là.
 */
export function parseAgentLabels(raw: string | null | undefined): string[] {
    if (typeof raw !== 'string') return [];
    return [...new Set(raw.split(SEPARATOR).map(normalizeLabel).filter((label) => label !== ''))];
}

/**
 * L'exigence d'une cible, normalisée — ou `null` pour « aucune ».
 *
 * La chaîne vide devient `null` délibérément : un champ de formulaire vidé signifie « plus
 * d'exigence », et le stocker tel quel donnerait une exigence que rien ne satisfait jamais.
 */
export function normalizeRequiredLabel(raw: string | null | undefined): string | null {
    if (typeof raw !== 'string') return null;
    const label = normalizeLabel(raw);
    return label === '' ? null : label;
}

/**
 * Cet agent peut-il exécuter un scan portant cette exigence ?
 *
 * Rendu à part de la requête SQL parce que la même décision est vérifiable des deux côtés :
 * la file filtre en base, et le distributeur peut confirmer sur la ligne qu'il a réellement
 * prise. Une règle écrite une seule fois, en SQL, se serait discutée à chaque relecture.
 */
export function agentAccepts(agentLabels: string[], required: string | null): boolean {
    if (required === null) return true;
    return agentLabels.includes(required);
}

function normalizeLabel(raw: string): string {
    return raw.trim().toLowerCase();
}
