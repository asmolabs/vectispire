import { compareSync, genSaltSync, hashSync } from 'bcryptjs';

/**
 * Hachage et vérification des mots de passe.
 *
 * **Les empreintes existantes doivent continuer de fonctionner.** La table `user` porte
 * des empreintes bcrypt écrites par l'implémentation Python ; elles sont interopérables
 * avec `bcryptjs`, donc la migration ne réinitialise aucun mot de passe. C'est vérifié
 * par des empreintes réellement produites par Python
 * (`test/vectors/bcrypt-python.json`), et non supposé.
 *
 * ## La troncature à 72 octets : ne rien faire est la bonne réponse
 *
 * L'algorithme bcrypt ignore ce qui dépasse 72 octets. Python tronquait explicitement
 * (`password.encode("utf-8")[:72]`), et il était tentant de reproduire ce geste ici.
 *
 * **C'est une erreur, et elle casse précisément le cas qu'elle croit protéger.**
 * `bcryptjs` encode lui-même la chaîne en UTF-8 puis tronque à 72 octets — donc le même
 * calcul, au même endroit. Tronquer en amont oblige à repasser des octets par une
 * chaîne, et le seul encodage qui transporte des octets arbitraires (`latin1`) est
 * ensuite ré-encodé en UTF-8 par la bibliothèque : les octets changent, l'empreinte
 * aussi. Mesuré sur « é » × 40 (80 octets, coupe au milieu du 37ᵉ caractère) : la chaîne
 * brute se vérifie, la version « tronquée » non.
 *
 * ## Le coût 12, et non 10
 *
 * `bcrypt.gensalt()` de Python vaut 12 depuis la version 4 ; `genSaltSync()` de
 * `bcryptjs` prend **10** par défaut. Laisser le défaut diviserait par quatre le travail
 * d'un attaquant sur toute empreinte réécrite après la bascule — sans qu'aucun test ne
 * le remarque, les deux coûts se vérifiant l'un l'autre.
 */

/** Le coût de Python ≥ 4.0. Ne pas laisser `bcryptjs` choisir le sien. */
export const BCRYPT_COST = 12;

export function hashPassword(password: string): string {
    return hashSync(password, genSaltSync(BCRYPT_COST));
}

/**
 * Ne lève jamais : une empreinte absente, vide ou malformée vaut « non ».
 *
 * Laisser une exception remonter d'ici transformerait une ligne corrompue en erreur 500
 * sur l'écran de connexion — à la fois moins clair pour l'utilisateur et plus bavard
 * envers quelqu'un qui sonde les comptes.
 */
export function verifyPassword(password: string, hash: string | null | undefined): boolean {
    if (!hash) return false;
    try {
        return compareSync(password, hash);
    } catch {
        return false;
    }
}
