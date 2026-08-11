/**
 * Ce qu'il reste de la manipulation d'horodatages : presque rien, et c'est le but.
 *
 * Les colonnes sont en `timestamptz` et les entités portent des `Date`. Il n'y a donc
 * plus ni parsing, ni canonicalisation, ni conversion vers du texte — les trois
 * fonctions qui vivaient ici existaient uniquement parce que la base stockait des
 * horodatages sans fuseau, héritage du schéma SQLAlchemy.
 *
 * Une seule règle subsiste : **quand un instant doit être comparé octet pour octet** —
 * dans une empreinte, dans un export — il s'écrit en ISO 8601 UTC à la milliseconde, par
 * `canonical()`. C'est `Date.prototype.toISOString`, nommé pour que l'intention soit
 * lisible à l'appel.
 */

/** L'instant présent. Nommé plutôt qu'écrit `new Date()` partout, pour que les tests
 *  aient un seul endroit à remplacer le jour où ils en auront besoin. */
export function now(): Date {
    return new Date();
}

/**
 * La forme comparable d'un instant : `YYYY-MM-DDTHH:MM:SS.sssZ`.
 *
 * Toujours en UTC et toujours à la milliseconde, quel que soit le fuseau de la machine.
 * Deux processus dans deux fuseaux doivent produire la même chaîne pour le même instant,
 * sans quoi une empreinte calculée ici ne se vérifie pas là.
 */
export function canonical(value: Date): string {
    return value.toISOString();
}
