import { refuseDeletion, refuseSelfLockout, validatePassword, validateRole, validateUsername } from './account-rules';

describe('règles de compte', () => {
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

        it('refuse au-delà de 72 octets plutôt que de laisser croire qu’ils protègent', () => {
            // bcrypt ignore la suite : accepter en silence donnerait un faux sentiment.
            expect(validatePassword('a'.repeat(73))).toMatch(/72 bytes/);
            // La limite est en octets : 24 caractères accentués font 48 octets, donc passent.
            expect(validatePassword('é'.repeat(24))).toBeNull();
            expect(validatePassword('é'.repeat(37))).toMatch(/72 bytes/);
        });
    });

    it('refuse un rôle hors vocabulaire', () => {
        expect(validateRole('ADMIN')).toBeNull();
        expect(validateRole('admin')).not.toBeNull();
        expect(validateRole('ROOT')).not.toBeNull();
    });

    describe('verrouillage hors de Zanshin', () => {
        const base = { isSelf: false, wasAdmin: true, willBeAdmin: true, willBeActive: true, remainingActiveAdmins: 1 };

        it('laisse passer une modification ordinaire', () => {
            expect(refuseSelfLockout(base)).toBeNull();
        });

        it('refuse de se désactiver soi-même', () => {
            expect(refuseSelfLockout({ ...base, isSelf: true, willBeActive: false })).not.toBeNull();
        });

        it('refuse de retirer son propre rôle administrateur', () => {
            expect(refuseSelfLockout({ ...base, isSelf: true, willBeAdmin: false })).not.toBeNull();
        });

        it("refuse de retirer le dernier administrateur actif, même sur le compte d'un autre", () => {
            expect(refuseSelfLockout({ ...base, willBeAdmin: false, remainingActiveAdmins: 0 })).toMatch(/dernier administrateur/);
            expect(refuseSelfLockout({ ...base, willBeActive: false, remainingActiveAdmins: 0 })).toMatch(/dernier administrateur/);
        });

        it("n'a rien à dire quand un autre administrateur reste", () => {
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
