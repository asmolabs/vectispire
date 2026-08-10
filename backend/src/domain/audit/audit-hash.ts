import { createHash } from 'node:crypto';
import { toPythonIsoformat } from '../common/python-timestamp';

/**
 * La chaîne d'intégrité du journal d'audit.
 *
 * Chaque entrée porte l'empreinte de la précédente. Modifier ou supprimer une ligne
 * passée casse toutes les empreintes qui suivent. Cela ne rend pas le journal
 * inaltérable — qui peut écrire dans la table peut réécrire toute la chaîne — mais
 * cela rend détectable la modification *sélective*, qui est la menace réaliste
 * quand la ligne intéressante est une parmi des milliers.
 *
 * **Ce calcul est un contrat de données, pas un détail d'implémentation.** La base
 * contient déjà des entrées écrites par l'implémentation Python. Si ce code produit
 * une empreinte différente, ne serait-ce que d'un octet, `verifyChain()` déclarera
 * falsifié tout l'historique antérieur à la migration. C'est exactement le mode de
 * panne qui avait fait retirer la prise en charge de MySQL : son type `DATETIME`
 * tronquait à la seconde, et le journal s'accusait lui-même.
 *
 * Les vecteurs de `test/vectors/audit-hash.json` sont générés depuis le code Python
 * par `scripts/generate_parity_vectors.py`, et `audit-hash.spec.ts` les rejoue.
 */

/** Les champs d'une entrée qui entrent dans son empreinte, dans cet ordre. */
export interface AuditEntryForHash {
    previousHash: string | null;
    /**
     * Sous une forme que `toPythonIsoformat` sait normaliser : le texte rendu par
     * PostgreSQL, ou déjà l'isoformat. **Pas un `Date`** pour une valeur relue de la
     * base : il ne porte pas la microseconde, et la perdre suffit à casser la chaîne.
     */
    timestamp: string | null;
    operationType: string | null;
    resourceId: string | null;
    userId: string | null;
    ipAddress: string | null;
    userAgent: string | null;
    description: string | null;
}

/**
 * `H(previous_hash | timestamp | operation | resource | user | ip | user_agent | description)`.
 *
 * L'ordre des champs est fixe, et le séparateur est un octet **NUL** : aucun contenu
 * ne peut alors imiter une frontière de champ. Sans cela, une description se terminant
 * par les bons caractères pourrait déplacer le sens du champ suivant — c'est ce que
 * vérifie le vecteur « description contenant un octet NUL ».
 *
 * `null` et chaîne vide sont volontairement indistinguables ici, comme en Python
 * (`entry.user_id or ""`).
 */
export function computeEntryHash(entry: AuditEntryForHash): string {
    const parts = [
        entry.previousHash ?? '',
        entry.timestamp ? toPythonIsoformat(entry.timestamp) : '',
        entry.operationType ?? '',
        entry.resourceId ?? '',
        entry.userId ?? '',
        entry.ipAddress ?? '',
        entry.userAgent ?? '',
        entry.description ?? ''
    ];
    return createHash('sha256').update(parts.join('\0'), 'utf8').digest('hex');
}

/** Une entrée telle qu'elle est relue pour vérification. */
export interface AuditEntryForVerification extends AuditEntryForHash {
    id: string;
    entryHash: string | null;
}

/**
 * `null` si la chaîne est intacte, sinon la description de la première rupture.
 *
 * Les entrées antérieures au chaînage ne portent pas d'empreinte : elles sont sautées
 * et comptées, parce que « ces lignes ne sont pas vérifiables » est une information,
 * pas une absence d'information. En revanche, une entrée sans empreinte *après* le
 * début du chaînage est une rupture : elle a été insérée.
 *
 * Attend les entrées de la plus ancienne à la plus récente.
 */
export function verifyChain(entries: AuditEntryForVerification[]): {
    broken: string | null;
    unverifiable: number;
} {
    let unverifiable = 0;
    let started = false;
    let expectedPrevious: string | null = null;

    for (const entry of entries) {
        if (!entry.entryHash) {
            if (started) {
                return {
                    broken: `Entrée ${entry.id} sans empreinte alors que le chaînage avait commencé : la ligne a été insérée ou modifiée.`,
                    unverifiable
                };
            }
            unverifiable += 1;
            continue;
        }

        if (started && entry.previousHash !== expectedPrevious) {
            return {
                broken: `Entrée ${entry.id} : empreinte précédente ${JSON.stringify(entry.previousHash)}, attendue ${JSON.stringify(expectedPrevious)} — une entrée antérieure a été modifiée ou supprimée.`,
                unverifiable
            };
        }
        if (entry.entryHash !== computeEntryHash(entry)) {
            return {
                broken: `Entrée ${entry.id} : son propre contenu ne correspond plus à son empreinte.`,
                unverifiable
            };
        }

        started = true;
        expectedPrevious = entry.entryHash;
    }

    return { broken: null, unverifiable };
}
