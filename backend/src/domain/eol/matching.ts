/**
 * L'appariement d'une version à son cycle de vie, et le verdict qui en découle.
 *
 * Fonctions pures : tout ce qui peut réellement se tromper ici — un préfixe de version
 * mal comparé, une date lue de travers, un purl portant son architecture — se teste sans
 * réseau. Le service qui les appelle ne fait que chercher les documents et les cacher.
 */

/** Une version d'un produit, telle que la publie endoflife.date. */
export interface Release {
    name?: string;
    eolFrom?: string | null;
    isEol?: boolean;
    isMaintained?: boolean;
    latest?: { name?: string } | null;
}

export interface Product {
    name?: string;
    releases?: Release[];
}

/** La fenêtre d'avertissement par défaut, en jours. */
export const DEFAULT_WARN_DAYS = 180;

/**
 * `pkg:type/namespace/nom`, sans version ni qualificatifs.
 *
 * Un purl de SBOM porte les deux (`pkg:rpm/redhat/openssl@3.5.1?arch=x86_64`) là où les
 * identifiants du catalogue n'en portent aucun : les deux côtés sont donc réduits à ce qui
 * désigne le **produit** et non la construction.
 */
export function normalizePurl(purl: string): string {
    let value = (purl ?? '').trim();
    for (const separator of ['?', '#']) value = value.split(separator, 1)[0];
    const at = value.lastIndexOf('@');
    if (at > 0) value = value.slice(0, at);
    return value.toLowerCase().replace(/\/+$/, '');
}

/**
 * Les composantes numériques d'une version, arrêtées à la première qui ne l'est pas.
 *
 * `« 9.7 (Plow) »` devient `['9','7']` et `« 3.12.1-rc1 »` devient `['3','12','1']` : ni la
 * version décorée d'une distribution ni le suffixe de construction d'un paquet ne doivent
 * empêcher de reconnaître le cycle.
 */
export function versionParts(version: string): string[] {
    const cleaned = (version ?? '').trim().split(' ')[0];
    const parts: string[] = [];

    for (const chunk of cleaned.split('.')) {
        const digits = /^\d+/.exec(chunk)?.[0] ?? '';
        if (!digits) break;
        parts.push(digits);
    }
    return parts;
}

/**
 * Le cycle auquel appartient une version.
 *
 * **Comparé composante par composante, jamais par préfixe de chaîne** : « 3.14 » commence
 * par « 3.1 », donc un `startsWith` rangerait Python 3.14 dans le cycle 3.1 et annoncerait
 * une fin de support passée depuis des années. Le cycle le plus long qui correspond
 * l'emporte, pour qu'un produit publiant à la fois « 8 » et « 8.1 » se résolve bien.
 */
export function matchRelease(product: Product, version: string): Release | null {
    const wanted = versionParts(version);
    let best: Release | null = null;
    let bestLength = -1;

    for (const release of product.releases ?? []) {
        const parts = versionParts(String(release.name ?? ''));
        if (parts.length === 0 || parts.length > wanted.length) continue;
        if (parts.every((part, index) => wanted[index] === part) && parts.length > bestLength) {
            best = release;
            bestLength = parts.length;
        }
    }
    return best;
}

/** Le verdict sur un cycle : sa sévérité, ou `null` s'il est confortablement supporté. */
export interface Verdict {
    severity: 'high' | 'medium';
    eolDate: Date | null;
}

/**
 * Évalue un cycle à une date donnée.
 *
 * **Un cycle déjà échu est `high`** — non parce que quelque chose est cassé aujourd'hui,
 * mais parce que rien ne sera corrigé demain, ce qui n'est pas un « moyen » pour un
 * composant qu'on livre. Une échéance à venir est `medium` : un délai, pas un incident.
 *
 * Au-delà de la fenêtre, rien n'est rapporté : tout a une fin de vie un jour, et signaler
 * une version supportée encore trois ans apprendrait aux gens à filtrer ce type.
 */
export function assess(release: Release, today: Date, warnDays: number = DEFAULT_WARN_DAYS): Verdict | null {
    const eolDate = parseDate(release.eolFrom);

    if (release.isEol === true || (eolDate && eolDate <= today)) return { severity: 'high', eolDate };

    if (eolDate) {
        const daysLeft = Math.floor((eolDate.getTime() - today.getTime()) / 86_400_000);
        if (daysLeft >= 0 && daysLeft <= warnDays) return { severity: 'medium', eolDate };
    }

    // `isMaintained: false` sans date : le cas des produits abandonnés.
    if (release.isMaintained === false && !eolDate) return { severity: 'high', eolDate: null };

    return null;
}

/**
 * La version maintenue la plus récente — c'est-à-dire ce que « corriger » veut dire ici.
 *
 * Posée sur `fixVersions` pour qu'un constat de fin de vie se lise comme tous les autres
 * constats actionnables, à l'écran comme dans les exports.
 */
export function recommendedVersion(product: Product): string | null {
    for (const release of product.releases ?? []) {
        if (release.isMaintained && !release.isEol) return release.latest?.name || String(release.name ?? '') || null;
    }
    return null;
}

/** Une date ISO du catalogue, ou `null`. Rendue en UTC pour rester comparable. */
export function parseDate(value: unknown): Date | null {
    if (typeof value !== 'string' || value.length < 10) return null;
    const parsed = new Date(`${value.slice(0, 10)}T00:00:00Z`);
    return Number.isNaN(parsed.getTime()) ? null : parsed;
}

/** L'index purl → produit, lu de la réponse du catalogue. */
export function parseIdentifierIndex(payload: unknown): Map<string, string> {
    const index = new Map<string, string>();
    const result = (payload as { result?: unknown })?.result;
    if (!Array.isArray(result)) return index;

    for (const entry of result) {
        const identifier = (entry as { identifier?: unknown })?.identifier;
        const product = ((entry as { product?: { name?: unknown } })?.product?.name ?? '') as string;
        if (typeof identifier === 'string' && identifier && typeof product === 'string' && product.trim()) {
            index.set(normalizePurl(identifier), product.trim());
        }
    }
    return index;
}

/** Ce qu'un SBOM propose à la recherche : produit, version, étiquette, purl. */
export interface Candidate {
    product: string;
    version: string;
    label: string;
    purl: string | null;
}

/**
 * Les paquets d'un SBOM qui correspondent à un produit du catalogue.
 *
 * La distribution est traitée à part par le service : un SBOM Syft ne porte **aucun purl
 * pour le système d'exploitation lui-même**, alors que c'est la réponse la plus utile
 * pour une image de conteneur — celle qu'aucune recherche au niveau des paquets ne
 * trouverait.
 */
export function packageCandidates(sbom: Record<string, unknown>, index: Map<string, string>): Candidate[] {
    const artifacts = sbom.artifacts;
    if (!Array.isArray(artifacts) || index.size === 0) return [];

    const candidates: Candidate[] = [];
    for (const artifact of artifacts) {
        const purl = (artifact as { purl?: unknown })?.purl;
        const version = String((artifact as { version?: unknown })?.version ?? '').trim();
        if (typeof purl !== 'string' || !purl || !version) continue;

        const product = index.get(normalizePurl(purl));
        if (!product) continue;

        candidates.push({ product, version, label: String((artifact as { name?: unknown })?.name ?? product), purl });
    }
    return candidates;
}

/** La distribution d'une image, lue du bloc `distro` du SBOM. */
export function distroCandidate(sbom: Record<string, unknown>): { id: string; version: string; label: string } | null {
    const distro = (sbom.distro ?? {}) as Record<string, unknown>;
    const id = String(distro.id ?? '').trim().toLowerCase();
    const version = String(distro.versionID ?? '').trim();
    if (!id || !version) return null;

    return { id, version, label: String(distro.name ?? id) };
}
