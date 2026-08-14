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
 * `null` si le journal est intact, sinon la description de la première rupture.
 *
 * ## Un graphe, et non une file
 *
 * La vérification exigeait une chaîne strictement unique : chaque entrée devait pointer sur
 * celle qui la précédait dans la liste. **Deux instances web écrivant au même instant lisent
 * la même queue** et produisent deux entrées portant la même précédente ; la chaîne fourche,
 * et un journal parfaitement honnête se déclarait rompu. Une alerte fausse dans un contrôle
 * d'intégrité est pire qu'inutile — on apprend à l'ignorer, et elle couvre alors les vraies.
 *
 * Ce qui est vérifié ici ne dépend donc plus de l'ordre :
 *
 * 1. **Chaque entrée correspond à sa propre empreinte** — c'est ce qui détecte la
 *    modification d'une ligne, la menace réaliste quand la ligne intéressante est une parmi
 *    des milliers.
 * 2. **La précédente de chaque entrée existe encore** — c'est ce qui détecte la suppression
 *    d'une entrée dont quelqu'un descend.
 * 3. **Aucune entrée sans empreinte n'est postérieure au début du chaînage** — c'est ce qui
 *    détecte une ligne posée à la main. Les entrées antérieures au chaînage, elles, sont
 *    comptées et non signalées : « ces lignes ne sont pas vérifiables » est une information,
 *    pas une absence d'information.
 *
 * ## Ce que cela ne détecte plus, et il faut le dire
 *
 * **La suppression d'une entrée dont personne ne descend** — la dernière écrite, ou le bout
 * d'une branche. Rien ne pointe vers elle, donc rien ne manque après son départ. C'est le
 * prix payé pour ne plus crier au loup, et il est assumé : refermer ce cas demanderait de
 * sérialiser toutes les écritures d'audit, ce qui ferait attendre chaque action auditée
 * derrière les autres, aussi longtemps que dure leur transaction.
 *
 * L'ordre des entrées n'a plus d'importance pour cette fonction.
 */
export function verifyChain(entries: AuditEntryForVerification[]): {
    broken: string | null;
    unverifiable: number;
} {
    const chained = entries.filter((entry) => entry.entryHash);
    const unverifiable = entries.length - chained.length;

    // Toutes les empreintes présentes, pour savoir vers quoi il est légitime de pointer.
    const known = new Set(chained.map((entry) => entry.entryHash as string));

    // **Une entrée sans empreinte n'est légitime que si elle ne suit pas le chaînage.**
    // C'est le cas des lignes écrites avant que la chaîne n'existe. Le repère est
    // l'horodatage et non la position dans la liste : celle-ci ne veut plus rien dire depuis
    // que les branches concurrentes sont admises.
    //
    // Strictement postérieure, et non « à partir de » : une ligne héritée écrite dans la
    // même milliseconde que la première entrée chaînée — l'instant de la bascule — ne doit
    // pas déclencher d'alerte. Ce que cela concède est mince : une entrée forgée devrait
    // porter une date antérieure à tout le journal chaîné, donc se faire passer pour une
    // ligne d'avant la bascule, ce qui lui interdit d'imiter une action récente.
    const oldestChained = chained.reduce<number | null>(
        (oldest, entry) => (entry.timestamp && (oldest === null || entry.timestamp.getTime() < oldest) ? entry.timestamp.getTime() : oldest),
        null
    );
    for (const entry of entries) {
        if (entry.entryHash || oldestChained === null) continue;
        if (entry.timestamp && entry.timestamp.getTime() > oldestChained) {
            return {
                broken: `Entrée ${entry.id} sans empreinte alors que le chaînage avait commencé : la ligne a été insérée ou modifiée.`,
                unverifiable
            };
        }
    }

    for (const entry of chained) {
        if (entry.entryHash !== computeEntryHash(entry)) {
            return {
                broken: `Entrée ${entry.id} : son propre contenu ne correspond plus à son empreinte.`,
                unverifiable
            };
        }
        // `null` est légitime : c'est une racine. Il y en a une par branche, et une branche
        // par instance ayant écrit en même temps qu'une autre.
        if (entry.previousHash !== null && !known.has(entry.previousHash)) {
            return {
                broken: `Entrée ${entry.id} : sa précédente ${JSON.stringify(entry.previousHash)} a disparu du journal — une entrée antérieure a été supprimée.`,
                unverifiable
            };
        }
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
