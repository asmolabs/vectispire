import { createHash } from 'node:crypto';
import { canonical } from '../common/timestamp';

/**
 * La chaîne d'intégrité du journal d'audit.
 *
 * Chaque entrée porte l'empreinte de la précédente. Modifier ou supprimer une ligne
 * passée casse toutes les empreintes qui suivent. Cela ne rend pas le journal
 * inaltérable — qui peut écrire dans la table peut réécrire toute la chaîne — mais
 * cela rend détectable la modification *sélective*, qui est la menace réaliste quand la
 * ligne intéressante est une parmi des milliers.
 *
 * ## L'horodatage entre sous une forme canonique
 *
 * `canonical()`, soit ISO 8601 UTC à la milliseconde. Un contrôle de sécurité ne doit pas
 * dépendre de la façon dont un moteur rend ses dates : `.123000` et `.123` désignent le
 * même instant et donneraient deux empreintes. Deux processus dans deux fuseaux
 * produisent ainsi la même chaîne pour le même instant.
 *
 * Le séparateur de champs est l'octet NUL, qui ne peut apparaître dans aucune des valeurs
 * hachées — sans quoi deux entrées différentes pourraient produire la même
 * concaténation.
 */

/** Les champs d'une entrée qui entrent dans son empreinte, dans cet ordre. */
export interface AuditEntryForHash {
    previousHash: string | null;
    /**
     * L'instant tel que la base le rend. Canonicalisé ici, pas par l'appelant. */
    timestamp: Date | null;
    operationType: string | null;
    resourceId: string | null;
    userId: string | null;
    ipAddress: string | null;
    userAgent: string | null;
    description: string | null;
}

/**
 * `H(previous | timestamp | operation | resource | user | ip | user_agent | description)`.
 *
 * L'ordre des champs est fixe, et le séparateur est un octet **NUL** : aucun contenu ne
 * peut alors imiter une frontière de champ. Sans cela, une description se terminant par
 * les bons caractères pourrait déplacer le sens du champ suivant.
 *
 * `null` et chaîne vide sont indistinguables ici, délibérément : les deux signifient
 * « ce champ n'a pas de valeur », et les distinguer ferait dépendre l'empreinte de la
 * façon dont un pilote rend une colonne vide.
 */
export function computeEntryHash(entry: AuditEntryForHash): string {
    const parts = [
        entry.previousHash ?? '',
        entry.timestamp ? canonical(entry.timestamp) : '',
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
 * et comptées, parce que « ces lignes ne sont pas vérifiables » est une information, pas
 * une absence d'information. En revanche, une entrée sans empreinte *après* le début du
 * chaînage est une rupture : elle a été insérée.
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

/**
 * Recalcule toute la chaîne, de la plus ancienne à la plus récente.
 *
 * C'est l'opération de bascule : les entrées écrites par l'implémentation Python
 * portent des empreintes calculées sur l'ancienne formule et ne se vérifient plus.
 *
 * **Une opération à exécuter une fois, sous les yeux de quelqu'un.** Réécrire un journal
 * d'intégrité est précisément ce que ce journal existe pour rendre détectable : elle ne
 * doit jamais être déclenchée automatiquement, ni au démarrage, ni par une route.
 *
 * Ne modifie pas le contenu des entrées — seulement `previousHash` et `entryHash`.
 */
export function rebuildChain<T extends AuditEntryForVerification>(entries: T[]): T[] {
    let previousHash: string | null = null;
    for (const entry of entries) {
        entry.previousHash = previousHash;
        entry.entryHash = computeEntryHash(entry);
        previousHash = entry.entryHash;
    }
    return entries;
}
