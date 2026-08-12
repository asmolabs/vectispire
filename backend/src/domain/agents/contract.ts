/**
 * La version du contrat entre Zanshin et ses agents.
 *
 * **Un agent d'une version antérieure doit pouvoir refuser proprement.** Sans ce numéro,
 * un agent parlant l'ancien protocole recevrait une tâche qu'il interprète de travers et
 * rendrait un résultat plausible mais faux — un scan qui déclare un dépôt propre parce
 * qu'il n'a pas compris ce qu'on lui demandait de chercher.
 *
 * Le numéro ne change **que** lorsque l'ancien comportement devient incorrect : ajouter un
 * champ optionnel n'est pas une rupture, puisqu'un agent qui l'ignore fait exactement ce
 * qu'il faisait avant.
 */
export const CONTRACT_VERSION = '1';

/**
 * Ce contrat est-il compatible avec le nôtre ?
 *
 * Égalité stricte, délibérément. Une comparaison plus souple — « majeure identique » —
 * paraît accueillante et déplace la question : il faudrait alors décider, pour chaque
 * champ ajouté, si l'agent qui l'ignore reste correct. Le refus est bruyant, le correctif
 * est un déploiement, et l'opérateur sait quoi faire.
 */
export function isCompatibleContract(announced: string): boolean {
    return announced.trim() === CONTRACT_VERSION;
}
