import { refuseDeletion, refuseSelfLockout, validatePassword, validateRole, validateUsername } from './account-rules';

describe('account rules', () => {
    describe('identifiant', () => {
        it.each([['admin'], ['jean.dupont'], ['ci-bot_01']])('accepte %s', (value) => {
            expect(validateUsername(value)).toBeNull();
        });
        it.each([[''], ['a'], ['jean dupont'], ['jean@example.be'], ['x'.repeat(65)]])('refuse %p', (value) => {
            expect(validateUsername(value)).not.toBeNull();
        });
    });

    describe('mot de passe', () => {
        it('exige une longueur, et rien de plus', () => {
            expect(validatePassword('correct-cheval-batterie-agrafe')).toBeNull();
            expect(validatePassword('court')).toMatch(/12 characters/);
        });

        it('refuses past 72 bytes rather than letting anyone believe they protect', () => {
            // bcrypt ignore la suite : accepter en silence donnerait un faux sentiment.
            expect(validatePassword('a'.repeat(73))).toMatch(/72 bytes/);
            // The limit is in bytes: 24 accented characters are 48 bytes, so they pass.
            // The accents are load-bearing here — with ASCII this test would prove nothing.
            expect(validatePassword('é'.repeat(24))).toBeNull();
            expect(validatePassword('é'.repeat(37))).toMatch(/72 bytes/);
        });
    });

    it('refuses a role outside the vocabulary', () => {
        expect(validateRole('ADMIN')).toBeNull();
        expect(validateRole('admin')).not.toBeNull();
        expect(validateRole('ROOT')).not.toBeNull();
    });

    describe('verrouillage hors de Zanshin', () => {
        const base = { isSelf: false, wasAdmin: true, willBeAdmin: true, willBeActive: true, remainingActiveAdmins: 1 };

        it('laisse passer une modification ordinaire', () => {
            expect(refuseSelfLockout(base)).toBeNull();
        });

        it('refuses to deactivate yourself', () => {
            expect(refuseSelfLockout({ ...base, isSelf: true, willBeActive: false })).not.toBeNull();
        });

        it('refuses to remove your own administrator role', () => {
            expect(refuseSelfLockout({ ...base, isSelf: true, willBeAdmin: false })).not.toBeNull();
        });

        it("refuses to remove the last active administrator, even on somebody else's account", () => {
            expect(refuseSelfLockout({ ...base, willBeAdmin: false, remainingActiveAdmins: 0 })).toMatch(/dernier administrateur/);
            expect(refuseSelfLockout({ ...base, willBeActive: false, remainingActiveAdmins: 0 })).toMatch(/dernier administrateur/);
        });

        it("has nothing to say while another administrator remains", () => {
            expect(refuseSelfLockout({ ...base, willBeAdmin: false, remainingActiveAdmins: 1 })).toBeNull();
        });

        it('laisse promouvoir un compte ordinaire', () => {
            expect(refuseSelfLockout({ ...base, wasAdmin: false, willBeAdmin: true, remainingActiveAdmins: 0 })).toBeNull();
        });
    });

    describe('suppression', () => {
        it('refuse son propre compte', () => {
            expect(refuseDeletion({ isSelf: true, isAdmin: true, remainingActiveAdmins: 5 })).not.toBeNull();
        });
        it('refuse le dernier administrateur actif', () => {
            expect(refuseDeletion({ isSelf: false, isAdmin: true, remainingActiveAdmins: 0 })).toMatch(/dernier administrateur/);
        });
        it('laisse supprimer un compte ordinaire', () => {
            expect(refuseDeletion({ isSelf: false, isAdmin: false, remainingActiveAdmins: 0 })).toBeNull();
        });
    });
});
