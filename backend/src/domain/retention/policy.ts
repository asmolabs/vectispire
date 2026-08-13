/**
 * La politique de rétention des charges brutes de scanner.
 *
 * `Scan.sbom` et `Scan.cves` portent la sortie non retouchée des outils. Un scan de
 * conteneur sur une image JRE pèse environ 2,5 Mo de SBOM, et rien ne supprimait jamais
 * rien : la base grossit indéfiniment tant que l'ordonnanceur tourne.
 *
 * **Ce qui est purgé et ce qui est gardé est tout le sujet.**
 *
 * - *Purgé* : `sbom` et `cves`, les blocs bruts. Ils existent pour l'audit — « qu'a
 *   exactement rapporté Syft ce jour-là » — et cette valeur décroît vite.
 * - *Gardé, toujours* : `summary` et `findingsCount` (les chiffres qu'affiche
 *   l'historique), chaque constat, chaque problème. **La projection normalisée *est* le
 *   registre durable** — c'était l'objet de sa construction — donc purger un bloc ne
 *   coûte ni historique, ni triage, ni delta.
 *
 * Les deux règles se conjuguent, elles ne s'additionnent pas : un scan n'est purgeable
 * que s'il est **à la fois** hors de la fenêtre « les N derniers de cette cible » **et**
 * plus vieux que la limite d'âge. Exiger les deux fait qu'une cible scannée deux fois par
 * an garde ses charges, et qu'une cible scannée toutes les heures reste bornée — aucune
 * des deux règles seule n'obtient cela.
 */

export const SETTING_RETENTION_KEEP_PER_TARGET = 'retention_keep_per_target';
export const SETTING_RETENTION_MAX_AGE_DAYS = 'retention_max_age_days';

/**
 * Garder la sortie brute des dix derniers scans de chaque cible, et de tout ce qui date de
 * moins de quatre-vingt-dix jours. Défauts généreux : l'objet est de borner la croissance,
 * pas d'être avare, et un opérateur qui enquête sur une régression regarde des scans récents.
 */
export const DEFAULT_KEEP_PER_TARGET = 10;
export const DEFAULT_MAX_AGE_DAYS = 90;

/** Zéro sur un axe veut dire « pas de limite sur cet axe » ; zéro sur les deux désactive. */
export const UNLIMITED = 0;

export interface RetentionPolicy {
    keepPerTarget: number;
    maxAgeDays: number;
}

/** Une politique désactivée ne purge rien du tout. */
export function isEnabled(policy: RetentionPolicy): boolean {
    return policy.keepPerTarget !== UNLIMITED || policy.maxAgeDays !== UNLIMITED;
}

/**
 * Un réglage entier, ou son défaut.
 *
 * Une valeur illisible retombe sur le défaut plutôt que sur zéro : zéro veut dire « aucune
 * limite », donc une faute de frappe dans les réglages désactiverait la rétention en
 * silence et la base recommencerait à grossir sans que rien ne le dise.
 */
export function intSetting(raw: string, fallback: number): number {
    // La chaîne vide est écartée avant la conversion, et c'est le point : `Number('')`
    // vaut **0**, qui veut dire ici « aucune limite ». Un réglage absent désactiverait
    // donc la rétention au lieu d'appliquer son défaut, et la base recommencerait à
    // grossir sans que rien ne le dise.
    if (raw.trim() === '') return fallback;

    const value = Number(raw);
    if (!Number.isInteger(value) || value < 0) return fallback;
    return value;
}

/** La date avant laquelle un scan est assez vieux pour être purgé, ou `null` si sans limite. */
export function cutoffDate(policy: RetentionPolicy, now: Date): Date | null {
    if (policy.maxAgeDays === UNLIMITED) return null;
    return new Date(now.getTime() - policy.maxAgeDays * 86_400_000);
}

/** Un scan candidat, réduit à ce que la décision demande. */
export interface Candidate {
    id: number;
    repoId: number | null;
    containerId: number | null;
    createdAt: Date;
}

/**
 * Les scans dont les charges brutes peuvent être abandonnées.
 *
 * Les candidats doivent arriver **du plus récent au plus ancien**, cible par cible : c'est
 * cet ordre qui donne son sens au rang, et un tri différent purgerait les scans les plus
 * récents — précisément ceux pour lesquels les charges existent.
 */
export function prunable(candidates: Candidate[], policy: RetentionPolicy, now: Date): number[] {
    if (!isEnabled(policy)) return [];

    const cutoff = cutoffDate(policy, now);
    const rankPerTarget = new Map<string, number>();
    const ids: number[] = [];

    for (const candidate of candidates) {
        const target = candidate.repoId !== null ? `repo:${candidate.repoId}` : `container:${candidate.containerId}`;
        const rank = rankPerTarget.get(target) ?? 0;
        rankPerTarget.set(target, rank + 1);

        if (policy.keepPerTarget !== UNLIMITED && rank < policy.keepPerTarget) continue;
        if (cutoff !== null && candidate.createdAt >= cutoff) continue;
        ids.push(candidate.id);
    }
    return ids;
}
