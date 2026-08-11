/**
 * Validation d'une URL de dépôt.
 *
 * **Ce n'est pas une validation de saisie, c'est un contrôle de sécurité.** L'URL
 * atterrit dans un `git clone` exécuté par un agent : une valeur non contrôlée y est une
 * exécution de code arbitraire sur la machine qui scanne, pas un champ mal rempli. Elle
 * est donc vérifiée à la saisie *et* avant chaque clone, parce que des lignes
 * antérieures à cette validation existent en base.
 *
 * Deux formes acceptées, et rien d'autre : une URL à schéma explicite parmi
 * `https`/`ssh`/`git`, ou la forme SCP abrégée `git@hote:chemin` que tout le monde
 * copie depuis GitHub.
 */

const ALLOWED_SCHEMES = ['https:', 'ssh:', 'git:'];
const SCP_FORM = /^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:[A-Za-z0-9._\/-]+$/;

/** `null` si l'URL est acceptable, sinon le message à montrer. */
export function validateRepositoryUrl(url: string): string | null {
    if (!url) return "L'URL du dépôt est requise.";
    if (SCP_FORM.test(url)) return null;

    let parsed: URL;
    try {
        parsed = new URL(url);
    } catch {
        return "URL invalide. Attendu « https://… », « ssh://… » ou « git@hôte:chemin ».";
    }

    if (!ALLOWED_SCHEMES.includes(parsed.protocol)) {
        // `file://` clonerait un chemin local de l'agent ; `ext::` fait exécuter une
        // commande arbitraire par git lui-même. Une liste blanche est la seule forme
        // sûre ici.
        return `Schéma « ${parsed.protocol.replace(':', '')} » non autorisé. Attendu https, ssh ou git.`;
    }
    if (!parsed.hostname) return "L'URL doit désigner un hôte.";
    return null;
}
