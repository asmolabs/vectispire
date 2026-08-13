/**
 * La lecture des deux catalogues publics d'exploitation : EPSS et CISA KEV.
 *
 * Fonctions pures, séparées du service qui appelle le réseau — c'est ce qui permet de
 * tester la partie qui peut réellement se tromper (un champ renommé, un score en chaîne,
 * une entrée sans identifiant) sans dépendre d'une API distante.
 *
 * **Une charge illisible rend un résultat vide, jamais une exception.** L'enrichissement
 * est facultatif : un scan qui a produit de vrais résultats ne doit pas être marqué en
 * échec parce que FIRST a changé la forme de sa réponse.
 */

/** L'URL de l'API EPSS. Métadonnée seule : seuls des identifiants de CVE y sont envoyés. */
export const EPSS_API_URL = 'https://api.first.org/data/v1/epss';

/** Le catalogue des vulnérabilités activement exploitées, publié par la CISA. */
export const KEV_CATALOG_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

/**
 * La taille d'un lot d'interrogation EPSS.
 *
 * Sous la limite documentée par l'API : un lot trop grand se solde par un refus qui, ici,
 * serait avalé — donc par un enrichissement silencieusement absent plutôt que par une
 * erreur visible.
 */
export const EPSS_BATCH_SIZE = 90;

/** Les scores EPSS d'une réponse, indexés par CVE. */
export function parseEpssResponse(payload: unknown): Map<string, number> {
    const scores = new Map<string, number>();
    const data = (payload as { data?: unknown })?.data;
    if (!Array.isArray(data)) return scores;

    for (const entry of data) {
        const cve = (entry as { cve?: unknown })?.cve;
        const epss = (entry as { epss?: unknown })?.epss;
        if (typeof cve !== 'string' || cve === '') continue;

        // L'API rend le score en **chaîne** (« 0.00042 »), pas en nombre. Le prendre tel
        // quel le stockerait en texte dans une colonne numérique, ou le rendrait `NaN`.
        //
        // Le filtre sur le type précède la conversion, et ce n'est pas de la prudence
        // décorative : `Number(null)` et `Number('')` valent **0**, qui est un score EPSS
        // parfaitement légitime. Sans ce garde, un champ absent se lirait « probabilité
        // d'exploitation nulle » — l'absence déguisée en bonne nouvelle.
        if (typeof epss !== 'number' && (typeof epss !== 'string' || epss.trim() === '')) continue;
        const value = Number(epss);
        if (!Number.isFinite(value)) continue;
        scores.set(cve, value);
    }
    return scores;
}

/** Les identifiants du catalogue KEV. */
export function parseKevCatalog(payload: unknown): Set<string> {
    const vulnerabilities = (payload as { vulnerabilities?: unknown })?.vulnerabilities;
    if (!Array.isArray(vulnerabilities)) return new Set();

    return new Set(
        vulnerabilities
            .map((entry) => (entry as { cveID?: unknown })?.cveID)
            .filter((id): id is string => typeof id === 'string' && id !== '')
    );
}

/** Découpe une liste de CVE en lots interrogeables. */
export function batches<T>(items: T[], size: number = EPSS_BATCH_SIZE): T[][] {
    const result: T[][] = [];
    for (let index = 0; index < items.length; index += size) result.push(items.slice(index, index + size));
    return result;
}
