import { afterLapse, capacity, leaseHasLapsed, leaseUntil, LEASE_MS, MAX_ATTEMPTS } from './queue-rules';

describe('règles de la file de scans', () => {
    describe('capacité', () => {
        it('est ce qui reste sous la limite', () => {
            expect(capacity(5, 2)).toBe(3);
            expect(capacity(5, 5)).toBe(0);
        });

        it('ne devient jamais négative', () => {
            // Un opérateur qui abaisse la limite pendant que des scans tournent ne doit
            // pas obtenir une capacité négative, qui deviendrait une limite inversée.
            expect(capacity(2, 5)).toBe(0);
        });
    });

    describe('bail', () => {
        const asOf = new Date('2026-08-12T10:00:00Z');

        it('a lapsé quand sa date est passée', () => {
            expect(leaseHasLapsed(new Date('2026-08-12T09:59:59Z'), asOf)).toBe(true);
            expect(leaseHasLapsed(new Date('2026-08-12T10:00:01Z'), asOf)).toBe(false);
        });

        it('considère lapsé un bail absent', () => {
            // Un scan « en cours » sans bail est un scan dont personne ne répond : c'est
            // l'état qu'on trouve après un redémarrage brutal, et le laisser passer pour
            // vivant le rendrait irréclamable pour toujours.
            expect(leaseHasLapsed(null, asOf)).toBe(true);
        });

        it('court à partir de la réclamation', () => {
            expect(leaseUntil(asOf).getTime() - asOf.getTime()).toBe(LEASE_MS);
        });
    });

    describe('après expiration', () => {
        it('remet en file tant qu’il reste des tentatives', () => {
            expect(afterLapse(0)).toBe('requeue');
            expect(afterLapse(MAX_ATTEMPTS - 1)).toBe('requeue');
        });

        it('échoue une fois les tentatives épuisées', () => {
            // Sinon une cible qui bloque son travailleur à tous les coups circulerait
            // d'un agent à l'autre indéfiniment.
            expect(afterLapse(MAX_ATTEMPTS)).toBe('fail');
            expect(afterLapse(MAX_ATTEMPTS + 10)).toBe('fail');
        });
    });
});
