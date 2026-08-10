/**
 * Horodatages : lecture du texte rendu par la base, et forme canonique.
 *
 * Les colonnes de date sont des `timestamp without time zone` contenant de l'UTC, et
 * le pilote les rend en **texte** (voir `persistence/pg-types.ts`, qui explique
 * pourquoi il ne faut surtout pas les laisser devenir des `Date`).
 *
 * Deux formes circulent, et c'est délibéré :
 *
 * - **Le texte de la base**, dont la fraction est amputée de ses zéros de queue
 *   (`.123` pour 123 000 microsecondes, `.00001` pour 10) et qui utilise une espace
 *   comme séparateur. C'est ce qu'on lit et ce qu'on écrit.
 * - **La forme canonique**, `YYYY-MM-DDTHH:MM:SS.sssZ`, utilisée partout où un
 *   horodatage doit être comparé octet pour octet — dans un hachage, dans un export.
 *
 * La canonicalisation est ce qui rend la chaîne d'intégrité du journal d'audit
 * indépendante de la façon dont un moteur rend ses dates. La version précédente hachait
 * la forme que produisait `datetime.isoformat()` en Python, ce qui couplait un contrôle
 * de sécurité au format d'un langage : `.123000` et `.123` désignent le même instant et
 * donnaient deux empreintes différentes.
 *
 * **La précision canonique s'arrête à la milliseconde.** Le compromis est explicite :
 * la chaîne ne certifie plus l'ordre en deçà, ce dont rien ne dépendait — deux entrées
 * de la même milliseconde restent distinguées par leur contenu et par l'empreinte de
 * la précédente.
 */

const TIMESTAMP = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(?:Z|[+-]\d{2}:?\d{2})?$/;

export class InvalidTimestampError extends Error {
    constructor(value: unknown) {
        super(`Horodatage illisible : ${JSON.stringify(value)}`);
        this.name = 'InvalidTimestampError';
    }
}

export interface TimestampParts {
    year: number;
    month: number;
    day: number;
    hour: number;
    minute: number;
    second: number;
    /** 0 à 999 999, tel que la base le porte. */
    microsecond: number;
}

/**
 * Décompose le texte rendu par la base.
 *
 * La fraction est **complétée à droite** jusqu'à six chiffres : PostgreSQL retire les
 * zéros de queue, donc `.123` vaut 123 000 microsecondes et non 123. La lire comme un
 * entier la décalerait d'un facteur mille.
 *
 * Un suffixe de fuseau est accepté et ignoré : la colonne est sans fuseau, et si un
 * pilote en ajoute un, il vaut UTC.
 */
export function parseTimestamp(value: string): TimestampParts {
    const match = TIMESTAMP.exec(String(value).trim());
    if (!match) throw new InvalidTimestampError(value);

    const [, year, month, day, hour, minute, second, fraction] = match;
    return {
        year: Number(year),
        month: Number(month),
        day: Number(day),
        hour: Number(hour),
        minute: Number(minute),
        second: Number(second),
        microsecond: fraction ? Number(fraction.padEnd(6, '0')) : 0
    };
}

const pad = (value: number, width = 2) => String(value).padStart(width, '0');

/**
 * La forme canonique : `YYYY-MM-DDTHH:MM:SS.sssZ`, toujours, fraction comprise même
 * nulle.
 *
 * « Toujours » est le point : un format qui omet parfois la fraction fait dépendre une
 * empreinte de la valeur des microsecondes, ce qui est exactement le piège dont on
 * sort.
 */
export function canonicalTimestamp(value: string | TimestampParts): string {
    const parts = typeof value === 'string' ? parseTimestamp(value) : value;
    const millisecond = Math.floor(parts.microsecond / 1000);
    return (
        `${pad(parts.year, 4)}-${pad(parts.month)}-${pad(parts.day)}` +
        `T${pad(parts.hour)}:${pad(parts.minute)}:${pad(parts.second)}.${pad(millisecond, 3)}Z`
    );
}

/**
 * L'instant courant, sous la forme qu'attend une colonne `timestamp without time
 * zone` : UTC, sans suffixe de fuseau.
 *
 * Écrire un `Date` à la place réintroduirait la conversion de fuseau que
 * `persistence/pg-types.ts` retire côté lecture.
 */
export function nowForDatabase(): string {
    const now = new Date();
    return (
        `${now.getUTCFullYear()}-${pad(now.getUTCMonth() + 1)}-${pad(now.getUTCDate())}` +
        `T${pad(now.getUTCHours())}:${pad(now.getUTCMinutes())}:${pad(now.getUTCSeconds())}` +
        `.${pad(now.getUTCMilliseconds(), 3)}`
    );
}
