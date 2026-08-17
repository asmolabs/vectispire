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

describe('triage decision', () => {
    it('accepts the four statuses of the vocabulary', () => {
        for (const status of [TRIAGE_UNDER_REVIEW, TRIAGE_AFFECTED, TRIAGE_FIXED]) {
            expect(decideTriage({ status, actor: 'alice' }, NOW).status).toBe(status);
        }
        expect(decideTriage({ status: TRIAGE_NOT_AFFECTED, actor: 'alice', justification: 'component_not_present' }, NOW).status).toBe(TRIAGE_NOT_AFFECTED);
    });

    it('refuses a status outside the vocabulary', () => {
        expect(() => decideTriage({ status: 'maybe', actor: 'alice' }, NOW)).toThrow(InvalidTriageError);
    });

    describe('the VEX justification', () => {
        it('is required for not_affected', () => {
            // Without it the statement carries no information and the exported VEX
            // document would be invalid.
            expect(() => decideTriage({ status: TRIAGE_NOT_AFFECTED, actor: 'alice' }, NOW)).toThrow(/justification is required/);
        });

        it('must belong to the OpenVEX vocabulary', () => {
            expect(() => decideTriage({ status: TRIAGE_NOT_AFFECTED, actor: 'alice', justification: 'because' }, NOW)).toThrow(/Unknown VEX justification/);
        });

        it.each(VEX_JUSTIFICATIONS)('accepte « %s »', (justification) => {
            expect(decideTriage({ status: TRIAGE_NOT_AFFECTED, actor: 'alice', justification }, NOW).justification).toBe(justification);
        });

        it('treats an empty or blank justification as absent', () => {
            expect(() => decideTriage({ status: TRIAGE_NOT_AFFECTED, actor: 'alice', justification: '   ' }, NOW)).toThrow(/justification is required/);
            expect(decideTriage({ status: TRIAGE_AFFECTED, actor: 'alice', justification: '' }, NOW).justification).toBeNull();
        });

        it("is not required for the other statuses", () => {
            expect(decideTriage({ status: TRIAGE_FIXED, actor: 'alice' }, NOW).justification).toBeNull();
        });
    });

    it('normalizes the comment, empty becoming null', () => {
        expect(decideTriage({ status: TRIAGE_AFFECTED, actor: 'a', comment: '  texte  ' }, NOW).comment).toBe('texte');
        expect(decideTriage({ status: TRIAGE_AFFECTED, actor: 'a', comment: '   ' }, NOW).comment).toBeNull();
    });

    it('records who decided and when', () => {
        const decision = decideTriage({ status: TRIAGE_AFFECTED, actor: 'bob' }, NOW);
        expect(decision.triagedBy).toBe('bob');
        expect(decision.triagedAt).toBe(NOW);
    });
});

describe('review date', () => {
    it('is absent when nothing is asked for', () => {
        expect(expiryFrom(TRIAGE_AFFECTED, null, NOW)).toBeNull();
    });

    it('is cleared by a return to under review', () => {
        // The issue is already in the queue: a date to bring it back there would fire on
        // nothing.
        expect(expiryFrom(TRIAGE_UNDER_REVIEW, 90, NOW)).toBeNull();
    });

    it('adds the number of days requested', () => {
        expect(expiryFrom(TRIAGE_NOT_AFFECTED, 30, NOW)).toEqual(new Date('2026-09-09T08:13:58.322Z'));
    });

    it('crosses months and years correctly', () => {
        expect(expiryFrom(TRIAGE_AFFECTED, 1, new Date('2026-12-31T23:00:00Z'))).toEqual(new Date('2027-01-01T23:00:00Z'));
        // 2028 is a leap year: 29 February exists.
        expect(expiryFrom(TRIAGE_AFFECTED, 1, new Date('2028-02-28T12:00:00Z'))).toEqual(new Date('2028-02-29T12:00:00Z'));
    });

    it('keeps the fraction of a second as it is', () => {
        // Rebuilding it would risk reformatting it differently from Python.
        expect(expiryFrom(TRIAGE_AFFECTED, 7, new Date('2026-01-02T03:04:05.123Z'))).toEqual(new Date('2026-01-09T03:04:05.123Z'));
        expect(expiryFrom(TRIAGE_AFFECTED, 7, new Date('2026-01-02T03:04:05Z'))).toEqual(new Date('2026-01-09T03:04:05Z'));
    });

    it('refuses zero or a negative delay', () => {
        // Silently treating that as "never" would hide an arithmetic mistake by the
        // caller.
        expect(() => expiryFrom(TRIAGE_AFFECTED, 0, NOW)).toThrow(/at least one day/);
        expect(() => expiryFrom(TRIAGE_AFFECTED, -5, NOW)).toThrow(/at least one day/);
    });
});

describe('expiry of a decision', () => {
    const suppressed = { triageStatus: TRIAGE_NOT_AFFECTED, triageExpiresAt: new Date('2026-08-10T08:00:00Z') };

    it('recognizes an expired decision', () => {
        expect(isTriageExpired(suppressed, NOW)).toBe(true);
    });

    it('does not treat a decision with a future date as expired', () => {
        expect(isTriageExpired({ ...suppressed, triageExpiresAt: new Date('2027-01-01T00:00:00Z') }, NOW)).toBe(false);
    });

    it('ignores a decision with no date', () => {
        expect(isTriageExpired({ ...suppressed, triageExpiresAt: null }, NOW)).toBe(false);
    });

    it('ignores an issue already under review', () => {
        expect(isTriageExpired({ triageStatus: TRIAGE_UNDER_REVIEW, triageExpiresAt: new Date('2020-01-01T00:00:00Z') }, NOW)).toBe(false);
    });

    it('keeps the justification, the comment and the author', () => {
        // Erasing the text would turn a scheduled review into an investigation started
        // from scratch — the way a review date becomes something people stop filling in.
        // `triagedBy` is, on top of that, evidence of who said what.
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
