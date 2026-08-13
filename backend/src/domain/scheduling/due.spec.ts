import { InvalidCronExpression, cronDue, intervalDue, isTargetDue, validateExpression } from './due';

const NOW = new Date('2026-08-13T10:00:00.000Z');
const minutesAgo = (minutes: number) => new Date(NOW.getTime() - minutes * 60_000);

describe('intervalDue', () => {
    it("n'ordonnance jamais une cible sans intervalle", () => {
        expect(intervalDue(null, null, NOW)).toBe(false);
        expect(intervalDue(0, null, NOW)).toBe(false);
    });

    it('rend due immédiatement une cible jamais ordonnancée', () => {
        // Sinon activer l'ordonnanceur laisserait la cible attendre un intervalle entier —
        // une journée de silence avec le défaut de 1440 minutes, que l'opérateur lirait
        // comme un ordonnanceur cassé.
        expect(intervalDue(1440, null, NOW)).toBe(true);
    });

    it("attend que l'intervalle soit écoulé", () => {
        expect(intervalDue(60, minutesAgo(59), NOW)).toBe(false);
        expect(intervalDue(60, minutesAgo(60), NOW)).toBe(true);
    });
});

describe('cronDue', () => {
    it('rend due une cible jamais ordonnancée', () => {
        expect(cronDue('0 2 * * *', null, NOW)).toBe(true);
    });

    it("rattrape l'occurrence manquée d'un tour en retard", () => {
        // Calculée depuis le dernier tour et non depuis maintenant : un redémarrage ne doit
        // pas faire sauter la nuit.
        expect(cronDue('0 2 * * *', new Date('2026-08-11T02:00:00.000Z'), NOW)).toBe(true);
    });

    it("n'est pas due avant la prochaine occurrence", () => {
        expect(cronDue('0 2 * * *', new Date('2026-08-13T02:00:00.000Z'), NOW)).toBe(false);
    });

    it("n'envoie rien pour une expression inutilisable, même jamais ordonnancée", () => {
        // L'ordre compte : sans cette vérification avant le raccourci, la seule cible dont
        // la configuration est cassée serait aussi la seule à partir sans qu'on l'ait
        // demandé.
        expect(cronDue('n importe quoi', null, NOW)).toBe(false);
        expect(cronDue('', null, NOW)).toBe(false);
    });
});

describe('isTargetDue', () => {
    it("l'expression cron l'emporte sur l'intervalle", () => {
        // Un intervalle ne sait pas dire « toutes les nuits à deux heures » : il dérive, et
        // un scan réglé pour les heures creuses finit en pleine journée.
        const target = { scanCron: '0 2 * * *', scanIntervalMinutes: 1, lastScheduledScanAt: new Date('2026-08-13T02:00:00.000Z') };

        expect(isTargetDue(target, NOW)).toBe(false);
    });

    it("retombe sur l'intervalle quand l'expression est effacée", () => {
        const target = { scanCron: null, scanIntervalMinutes: 60, lastScheduledScanAt: minutesAgo(90) };

        expect(isTargetDue(target, NOW)).toBe(true);
    });
});

describe('validateExpression', () => {
    it('accepte une expression utilisable et la normalise', () => {
        expect(validateExpression('  0 2 * * *  ')).toBe('0 2 * * *');
    });

    it('traite le vide comme « pas de cron »', () => {
        // C'est ainsi qu'un opérateur revient à l'ordonnancement par intervalle.
        expect(validateExpression('')).toBeNull();
        expect(validateExpression(null)).toBeNull();
    });

    it("refuse au point de saisie, avec un message actionnable", () => {
        // Découvrir le rejet en regardant des scans ne pas se produire est la manière chère.
        expect(() => validateExpression('tous les jours')).toThrow(InvalidCronExpression);
        expect(() => validateExpression('99 99 * * *')).toThrow(/Format attendu/);
    });
});
