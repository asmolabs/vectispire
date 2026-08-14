/**
 * Quelles dépendances le projet a réellement demandées.
 *
 * Chaque vulnérabilité arrivait avec la même quantité d'information sur *quoi faire* :
 * aucune. Un CVE critique dans un paquet déclaré au manifeste se corrige cet après-midi en
 * changeant une ligne ; le même CVE quatre niveaux plus bas, tiré par autre chose, attend
 * une publication en amont et demande peut-être un épinglage, un fork, ou la décision
 * d'accepter le risque. Classés à l'identique, ils produisent un backlog que personne ne
 * termine — et les transitifs, majoritaires, enterrent la poignée d'actionnables du jour.
 *
 * **Syft répond déjà à cette question et la réponse était jetée.** Le SBOM porte des
 * relations `dependency-of`, où le *parent* est la dépendance et l'*enfant* ce qui en
 * dépend. Un paquet qui n'apparaît jamais comme parent est donc une racine du graphe :
 * exactement « le projet a déclaré ceci ».
 *
 * **Le point important est ce qui se passe quand le graphe est absent.** Certains
 * catalogueurs n'émettent aucune arête, et alors *tout* paquet ressemble à une racine —
 * ce qui étiquetterait une image entière « dépendances directes ». C'est pire que de ne
 * rien dire : c'est une réponse fausse et assurée sur le champ censé décider quoi corriger
 * en premier. Un graphe vide rend donc `null` — inconnu — partout.
 */

const DEPENDENCY_OF = 'dependency-of';

/** `true` directe, `false` transitive, `null` inconnu. */
export type Directness = boolean | null;

export class DependencyDirectness {
    private readonly byPurl = new Map<string, boolean>();
    private readonly byNameVersion = new Map<string, boolean>();

    /** Le graphe portait-il des arêtes ? Sinon, tout est inconnu. */
    readonly available: boolean;

    constructor(sbom: Record<string, unknown> | null) {
        const artifacts = (sbom?.artifacts ?? []) as Record<string, unknown>[];
        const relationships = (sbom?.artifactRelationships ?? []) as Record<string, unknown>[];

        if (!Array.isArray(artifacts) || artifacts.length === 0) {
            this.available = false;
            return;
        }

        const dependedUpon = new Set<string>();
        if (Array.isArray(relationships)) {
            for (const relation of relationships) {
                if (relation.type === DEPENDENCY_OF && typeof relation.parent === 'string' && relation.parent) {
                    dependedUpon.add(relation.parent);
                }
            }
        }

        if (dependedUpon.size === 0) {
            this.available = false;
            return;
        }
        this.available = true;

        for (const artifact of artifacts) {
            const isDirect = typeof artifact.id === 'string' ? !dependedUpon.has(artifact.id) : false;

            // Un purl porte déjà la version, donc deux versions d'un même paquet gardent
            // des réponses distinctes — ce qui compte, car l'une peut être déclarée et
            // l'autre traînée par autre chose.
            if (typeof artifact.purl === 'string' && artifact.purl) {
                this.byPurl.set(artifact.purl, (this.byPurl.get(artifact.purl) ?? false) || isDirect);
            }
            if (typeof artifact.name === 'string' && artifact.name) {
                const key = `${artifact.name}@${artifact.version ?? ''}`;
                this.byNameVersion.set(key, (this.byNameVersion.get(key) ?? false) || isDirect);
            }
        }
    }

    /**
     * La réponse pour un paquet.
     *
     * **Le purl d'abord** : c'est l'identité qualifiée par l'écosystème, et c'est ce que
     * portent les correspondances de Grype comme les constats de licence. Le couple
     * nom+version est le repli pour un catalogueur qui n'a produit aucun purl ;
     * l'appariement sur le nom seul n'est **délibérément pas tenté**, puisque deux versions
     * d'un même paquet peuvent tomber de part et d'autre de cette réponse.
     */
    of(purl?: string | null, name?: string | null, version?: string | null): Directness {
        if (!this.available) return null;

        if (purl && this.byPurl.has(purl)) return this.byPurl.get(purl)!;
        if (name) {
            const key = `${name}@${version ?? ''}`;
            if (this.byNameVersion.has(key)) return this.byNameVersion.get(key)!;
        }
        return null;
    }

    /** Combien de paquets sont directs — pour le journal, et pour se rassurer sur le graphe. */
    get directCount(): number {
        return [...this.byPurl.values()].filter(Boolean).length;
    }
}
