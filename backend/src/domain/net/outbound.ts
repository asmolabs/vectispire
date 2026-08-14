/**
 * L'appel sortant de Zanshin, avec la politique qui va avec.
 *
 * **`validateOutboundUrl` ne protège que la première requête.** Node suit les redirections
 * par défaut : une destination validée qui répond `302 Location: http://169.254.169.254/`
 * est suivie sans que rien ne revérifie quoi que ce soit, et tout le garde d'URL tombe.
 * Vérifié en montant deux serveurs locaux — la requête atteignait bien la cible interne.
 *
 * Le cas le plus coûteux n'est pas le webhook mais **la revue par modèle** : son garde exige
 * une destination interne précisément parce qu'elle reçoit le code source du dépôt scanné.
 * Une redirection vers l'extérieur en ferait un canal d'exfiltration parfaitement silencieux,
 * bien formé, et invisible pour toute vérification anti-SSRF faite en amont.
 *
 * **Une seule définition, pour que le sixième appel hérite de la règle.** Elle était absente
 * des cinq appels existants — chacun l'aurait fallu, aucun ne l'avait — et la recopier cinq
 * fois aurait garanti qu'elle manque au suivant.
 *
 * Refuser plutôt que réémettre vers la nouvelle adresse : un point de terminaison qui
 * redirige est mal configuré, et l'erreur nomme le problème là où un suivi silencieux le
 * cacherait.
 */

/** Ce que toute requête sortante de Zanshin porte, quelle que soit sa destination. */
export interface OutboundRequest {
    method?: string;
    body?: unknown;
    headers?: Record<string, string>;
    timeoutMs: number;
}

/**
 * Émet la requête et rend la réponse. **Lève sur une redirection comme sur un statut
 * d'erreur** — l'appelant décide si c'est fatal.
 */
export async function outboundFetch(url: string, request: OutboundRequest): Promise<Response> {
    const { method = 'GET', body, headers = {}, timeoutMs } = request;

    const response = await fetch(url, {
        method,
        headers: body === undefined ? headers : { 'content-type': 'application/json', ...headers },
        body: body === undefined ? undefined : JSON.stringify(body),
        // La ligne qui porte tout le propos de ce module.
        redirect: 'error',
        signal: AbortSignal.timeout(timeoutMs)
    });

    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return response;
}

/** La même, quand la réponse est du JSON qu'on veut lire. */
export async function outboundJson<T>(url: string, request: OutboundRequest): Promise<T> {
    return (await outboundFetch(url, request)).json() as Promise<T>;
}
