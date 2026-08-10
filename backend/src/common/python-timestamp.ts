/**
 * Horodatages à la microseconde, au format que produit `datetime.isoformat()` en Python.
 *
 * **Pourquoi ce module existe.** Deux valeurs de Zanshin sont hachées, et l'horodatage
 * entre dans l'une d'elles : la chaîne d'intégrité du journal d'audit. Reproduire ce
 * hachage impose de reproduire la *chaîne de caractères* exacte que Python produisait,
 * et aucune fonction JavaScript native ne le fait :
 *
 * | valeur                     | Python `isoformat()`          | JS `toISOString()`          |
 * |----------------------------|-------------------------------|-----------------------------|
 * | 2026-08-10 08:13:58.322451 | `2026-08-10T08:13:58.322451`  | `2026-08-10T08:13:58.322Z`  |
 * | 2026-08-10 08:13:58.000000 | `2026-08-10T08:13:58`         | `2026-08-10T08:13:58.000Z`  |
 * | 2026-01-02 03:04:05.123000 | `2026-01-02T03:04:05.123000`  | `2026-01-02T03:04:05.123Z`  |
 *
 * Trois écarts, chacun suffisant à casser la chaîne : le suffixe `Z`, la fraction
 * réduite à trois chiffres, et la fraction écrite même quand elle est nulle.
 *
 * **Et un piège plus profond : `Date` ne sait pas représenter une microseconde.** Sa
 * résolution est la milliseconde. Lire une colonne `timestamp` de PostgreSQL dans un
 * `Date` perd donc les trois derniers chiffres, définitivement — et le hachage recalculé
 * ne correspondra plus, sans qu'aucune erreur ne soit levée. C'est pourquoi les
 * horodatages qui entrent dans un hachage sont manipulés ici comme des **chaînes**, de
 * bout en bout, jamais convertis en `Date` au passage.
 *
 * Les valeurs sont naïves : la base stocke de l'UTC sans fuseau (`timestamp without
 * time zone`), et `zanshin/clock.py` le garantit côté écriture. Aucune conversion de
 * fuseau n'a lieu ici, et c'est délibéré : en introduire une décalerait silencieusement
 * tout l'historique selon le réglage de la machine qui exécute le code.
 */

/** Un horodatage décomposé, à la précision de la microseconde. */
export interface PythonTimestampParts {
    year: number;
    month: number;
    day: number;
    hour: number;
    minute: number;
    second: number;
    /** 0 à 999 999. */
    microsecond: number;
}

const POSTGRES_OR_ISO =
    /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(?:Z|[+-]\d{2}:?\d{2})?$/;

export class InvalidTimestampError extends Error {
    constructor(value: string) {
        super(`Horodatage illisible : ${JSON.stringify(value)}`);
        this.name = 'InvalidTimestampError';
    }
}

/**
 * Décompose le texte rendu par PostgreSQL — ou déjà au format isoformat.
 *
 * PostgreSQL sépare la date et l'heure par une espace et **retire les zéros de queue**
 * de la fraction : 123000 microsecondes reviennent en `.123`, et 10 microsecondes en
 * `.00001`. La fraction est donc complétée à droite jusqu'à six chiffres, et non lue
 * comme un nombre — `.123` vaut 123000 microsecondes, pas 123.
 *
 * Un éventuel suffixe de fuseau est accepté et ignoré : la colonne est sans fuseau, et
 * si un pilote en ajoute un, il vaut UTC.
 */
export function parsePythonTimestamp(value: string): PythonTimestampParts {
    const match = POSTGRES_OR_ISO.exec(value.trim());
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

const pad = (value: number, width: number) => String(value).padStart(width, '0');

/** Formate des composantes au format `datetime.isoformat()`. */
export function formatPythonTimestamp(parts: PythonTimestampParts): string {
    const base = `${pad(parts.year, 4)}-${pad(parts.month, 2)}-${pad(parts.day, 2)}T${pad(parts.hour, 2)}:${pad(parts.minute, 2)}:${pad(parts.second, 2)}`;
    // Python omet entièrement la fraction quand elle est nulle. Écrire « .000000 »
    // produirait un hachage différent pour la même instant.
    return parts.microsecond === 0 ? base : `${base}.${pad(parts.microsecond, 6)}`;
}

/**
 * Normalise vers la forme qui entre dans un hachage.
 *
 * Accepte le texte d'un pilote, une valeur déjà normalisée, ou un `Date` — ce dernier
 * **au prix de la microseconde**, qu'il ne porte pas. Ne lui passez un `Date` que pour
 * une valeur que vous venez de créer et qui n'a jamais transité par la base.
 */
export function toPythonIsoformat(value: string | Date | PythonTimestampParts): string {
    if (typeof value === 'string') return formatPythonTimestamp(parsePythonTimestamp(value));
    if (value instanceof Date) {
        if (Number.isNaN(value.getTime())) throw new InvalidTimestampError(String(value));
        return formatPythonTimestamp({
            year: value.getUTCFullYear(),
            month: value.getUTCMonth() + 1,
            day: value.getUTCDate(),
            hour: value.getUTCHours(),
            minute: value.getUTCMinutes(),
            second: value.getUTCSeconds(),
            microsecond: value.getUTCMilliseconds() * 1000
        });
    }
    return formatPythonTimestamp(value);
}
