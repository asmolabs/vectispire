import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { InvalidTimestampError, formatPythonTimestamp, parsePythonTimestamp, toPythonIsoformat } from './python-timestamp';

interface TimestampVector {
    isoformat: string;
    postgres: string;
    microsecond: number;
}

const vectors: TimestampVector[] = JSON.parse(readFileSync(join(__dirname, '../../../test/vectors/python-timestamp.json'), 'utf8'));

describe('horodatages au format Python', () => {
    it('dispose de vecteurs générés depuis le code Python', () => {
        // Si le fichier est vide, tout ce qui suit passerait sans rien vérifier.
        expect(vectors.length).toBeGreaterThan(0);
    });

    describe.each(vectors)('$isoformat', (vector) => {
        it('reconstruit isoformat depuis le rendu PostgreSQL', () => {
            expect(toPythonIsoformat(vector.postgres)).toBe(vector.isoformat);
        });

        it('est idempotent sur sa propre sortie', () => {
            expect(toPythonIsoformat(vector.isoformat)).toBe(vector.isoformat);
        });

        it('conserve la microseconde exacte', () => {
            expect(parsePythonTimestamp(vector.postgres).microsecond).toBe(vector.microsecond);
        });
    });

    describe('les écarts avec toISOString(), qui sont la raison de ce module', () => {
        it("omet la fraction quand elle est nulle, là où toISOString() écrit '.000Z'", () => {
            expect(toPythonIsoformat('2026-08-10 08:13:58')).toBe('2026-08-10T08:13:58');
            expect(new Date('2026-08-10T08:13:58Z').toISOString()).toBe('2026-08-10T08:13:58.000Z');
        });

        it("écrit six chiffres de fraction, là où toISOString() en écrit trois", () => {
            expect(toPythonIsoformat('2026-01-02 03:04:05.123')).toBe('2026-01-02T03:04:05.123000');
        });

        it('ne suffixe jamais Z', () => {
            expect(toPythonIsoformat('2026-01-02 03:04:05.5')).not.toContain('Z');
        });
    });

    describe('la fraction PostgreSQL est complétée à droite, pas lue comme un nombre', () => {
        // « .123 » vaut 123 000 microsecondes. La lire comme l'entier 123 décalerait
        // la valeur d'un facteur mille et casserait la chaîne d'audit en silence.
        it.each([
            ['.1', 100000],
            ['.12', 120000],
            ['.123', 123000],
            ['.000001', 1],
            ['.00001', 10]
        ])('%s vaut %d microsecondes', (fraction, expected) => {
            expect(parsePythonTimestamp(`2026-01-02 03:04:05${fraction}`).microsecond).toBe(expected);
        });
    });

    describe('formes acceptées', () => {
        it('accepte le séparateur T comme l’espace', () => {
            expect(toPythonIsoformat('2026-01-02T03:04:05.5')).toBe(toPythonIsoformat('2026-01-02 03:04:05.5'));
        });

        it('ignore un suffixe de fuseau : la colonne est sans fuseau et vaut UTC', () => {
            expect(toPythonIsoformat('2026-01-02 03:04:05.5+00:00')).toBe('2026-01-02T03:04:05.500000');
            expect(toPythonIsoformat('2026-01-02 03:04:05.5Z')).toBe('2026-01-02T03:04:05.500000');
        });

        it('refuse ce qu’il ne sait pas lire plutôt que de deviner', () => {
            // Deviner produirait une empreinte plausible et fausse, c'est-à-dire le
            // pire résultat possible pour un journal d'intégrité.
            expect(() => toPythonIsoformat('hier')).toThrow(InvalidTimestampError);
            expect(() => toPythonIsoformat('')).toThrow(InvalidTimestampError);
            expect(() => toPythonIsoformat(new Date('nawak'))).toThrow(InvalidTimestampError);
        });
    });

    describe('le passage par Date perd la microseconde', () => {
        // Documenté par un test plutôt que par un commentaire : c'est la raison pour
        // laquelle les horodatages hachés circulent en chaînes de bout en bout.
        it('ne conserve que la milliseconde', () => {
            const parts = parsePythonTimestamp('2026-08-10 08:13:58.322451');
            const viaDate = new Date(Date.UTC(parts.year, parts.month - 1, parts.day, parts.hour, parts.minute, parts.second, Math.floor(parts.microsecond / 1000)));
            expect(toPythonIsoformat(viaDate)).toBe('2026-08-10T08:13:58.322000');
            expect(formatPythonTimestamp(parts)).toBe('2026-08-10T08:13:58.322451');
        });
    });
});
