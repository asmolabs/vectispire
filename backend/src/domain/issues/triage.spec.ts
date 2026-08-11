import {
    InvalidTriageError,
    TRIAGE_AFFECTED,
    TRIAGE_FIXED,
    TRIAGE_NOT_AFFECTED,
    TRIAGE_UNDER_REVIEW,
    VEX_JUSTIFICATIONS,
    decideTriage,
    expireTriage,
    expiryFrom,
    isTriageExpired
} from './triage';

const NOW = new Date('2026-08-10T08:13:58.322Z');

describe('décision de triage', () => {
    it('accepte les quatre statuts du vocabulaire', () => {
        for (const status of [TRIAGE_UNDER_REVIEW, TRIAGE_AFFECTED, TRIAGE_FIXED]) {
            expect(decideTriage({ status, actor: 'alice' }, NOW).status).toBe(status);
        }
        expect(decideTriage({ status: TRIAGE_NOT_AFFECTED, actor: 'alice', justification: 'component_not_present' }, NOW).status).toBe(TRIAGE_NOT_AFFECTED);
    });

    it('refuse un statut hors vocabulaire', () => {
        expect(() => decideTriage({ status: 'peut-être', actor: 'alice' }, NOW)).toThrow(InvalidTriageError);
    });

    describe('la justification VEX', () => {
        it('est exigée pour « not_affected »', () => {
            // Sans elle, la déclaration ne porte aucune information et le document VEX
            // exporté serait invalide.
            expect(() => decideTriage({ status: TRIAGE_NOT_AFFECTED, actor: 'alice' }, NOW)).toThrow(/justification est requise/);
        });

        it('doit appartenir au vocabulaire OpenVEX', () => {
            expect(() => decideTriage({ status: TRIAGE_NOT_AFFECTED, actor: 'alice', justification: 'parce que' }, NOW)).toThrow(/Justification VEX inconnue/);
        });

        it.each(VEX_JUSTIFICATIONS)('accepte « %s »', (justification) => {
            expect(decideTriage({ status: TRIAGE_NOT_AFFECTED, actor: 'alice', justification }, NOW).justification).toBe(justification);
        });

        it('traite une justification vide ou blanche comme absente', () => {
            expect(() => decideTriage({ status: TRIAGE_NOT_AFFECTED, actor: 'alice', justification: '   ' }, NOW)).toThrow(/justification est requise/);
            expect(decideTriage({ status: TRIAGE_AFFECTED, actor: 'alice', justification: '' }, NOW).justification).toBeNull();
        });

        it("n'est pas exigée pour les autres statuts", () => {
            expect(decideTriage({ status: TRIAGE_FIXED, actor: 'alice' }, NOW).justification).toBeNull();
        });
    });

    it('normalise le commentaire, vide devenant null', () => {
        expect(decideTriage({ status: TRIAGE_AFFECTED, actor: 'a', comment: '  texte  ' }, NOW).comment).toBe('texte');
        expect(decideTriage({ status: TRIAGE_AFFECTED, actor: 'a', comment: '   ' }, NOW).comment).toBeNull();
    });

    it('enregistre qui a décidé et quand', () => {
        const decision = decideTriage({ status: TRIAGE_AFFECTED, actor: 'bob' }, NOW);
        expect(decision.triagedBy).toBe('bob');
        expect(decision.triagedAt).toBe(NOW);
    });
});

describe('date de révision', () => {
    it('est absente quand rien n’est demandé', () => {
        expect(expiryFrom(TRIAGE_AFFECTED, null, NOW)).toBeNull();
    });

    it('est effacée par un retour sous revue', () => {
        // Le problème est déjà dans la file : une date pour l'y ramener ne
        // déclencherait sur rien.
        expect(expiryFrom(TRIAGE_UNDER_REVIEW, 90, NOW)).toBeNull();
    });

    it('ajoute le nombre de jours demandé', () => {
        expect(expiryFrom(TRIAGE_NOT_AFFECTED, 30, NOW)).toEqual(new Date('2026-09-09T08:13:58.322Z'));
    });

    it('franchit correctement les mois et les années', () => {
        expect(expiryFrom(TRIAGE_AFFECTED, 1, new Date('2026-12-31T23:00:00Z'))).toEqual(new Date('2027-01-01T23:00:00Z'));
        // 2028 est bissextile : le 29 février existe.
        expect(expiryFrom(TRIAGE_AFFECTED, 1, new Date('2028-02-28T12:00:00Z'))).toEqual(new Date('2028-02-29T12:00:00Z'));
    });

    it('conserve la fraction de seconde telle quelle', () => {
        // La reconstruire risquerait de la reformater autrement que Python.
        expect(expiryFrom(TRIAGE_AFFECTED, 7, new Date('2026-01-02T03:04:05.123Z'))).toEqual(new Date('2026-01-09T03:04:05.123Z'));
        expect(expiryFrom(TRIAGE_AFFECTED, 7, new Date('2026-01-02T03:04:05Z'))).toEqual(new Date('2026-01-09T03:04:05Z'));
    });

    it('refuse zéro ou un délai négatif', () => {
        // Traiter cela en silence comme « jamais » masquerait une erreur de calcul de
        // l'appelant.
        expect(() => expiryFrom(TRIAGE_AFFECTED, 0, NOW)).toThrow(/au moins un jour/);
        expect(() => expiryFrom(TRIAGE_AFFECTED, -5, NOW)).toThrow(/au moins un jour/);
    });
});

describe('expiration d’une décision', () => {
    const suppressed = { triageStatus: TRIAGE_NOT_AFFECTED, triageExpiresAt: new Date('2026-08-10T08:00:00Z') };

    it('reconnaît une décision échue', () => {
        expect(isTriageExpired(suppressed, NOW)).toBe(true);
    });

    it('ne considère pas échue une décision dont la date est à venir', () => {
        expect(isTriageExpired({ ...suppressed, triageExpiresAt: new Date('2027-01-01T00:00:00Z') }, NOW)).toBe(false);
    });

    it('ignore une décision sans date', () => {
        expect(isTriageExpired({ ...suppressed, triageExpiresAt: null }, NOW)).toBe(false);
    });

    it('ignore un problème déjà sous revue', () => {
        expect(isTriageExpired({ triageStatus: TRIAGE_UNDER_REVIEW, triageExpiresAt: new Date('2020-01-01T00:00:00Z') }, NOW)).toBe(false);
    });

    it('conserve la justification, le commentaire et l’auteur', () => {
        // Effacer le texte transformerait un réexamen programmé en enquête repartie de
        // zéro — la façon dont une date de révision devient une chose qu'on cesse de
        // renseigner. `triagedBy` est de surcroît une preuve de qui a dit quoi.
        const issue = {
            triageStatus: TRIAGE_NOT_AFFECTED,
            triageExpiresAt: new Date('2026-08-10T08:00:00Z'),
            triageJustification: 'component_not_present',
            triageComment: 'Module absent de l’image de production.',
            triagedBy: 'alice',
            triagedAt: new Date('2026-02-01T09:00:00Z')
        };

        const expired = expireTriage(issue);

        expect(expired.triageStatus).toBe(TRIAGE_UNDER_REVIEW);
        expect(expired.triageExpiresAt).toBeNull();
        expect(expired.triageJustification).toBe('component_not_present');
        expect(expired.triageComment).toBe('Module absent de l’image de production.');
        expect(expired.triagedBy).toBe('alice');
        expect(expired.triagedAt).toEqual(new Date('2026-02-01T09:00:00Z'));
    });
});
