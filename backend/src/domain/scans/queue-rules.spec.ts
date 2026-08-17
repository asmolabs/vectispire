import { afterLapse, capacity, leaseHasLapsed, leaseUntil, LEASE_MS, MAX_ATTEMPTS } from './queue-rules';

describe('scan queue rules', () => {
    describe('capacity', () => {
        it('est ce qui reste sous la limite', () => {
            expect(capacity(5, 2)).toBe(3);
            expect(capacity(5, 5)).toBe(0);
        });

        it('never goes negative', () => {
            // An operator lowering the limit while scans are running must not end up with
            // a negative capacity, which would become an inverted limit.
            expect(capacity(2, 5)).toBe(0);
        });
    });

    describe('bail', () => {
        const asOf = new Date('2026-08-12T10:00:00Z');

        it('has lapsed once its date has passed', () => {
            expect(leaseHasLapsed(new Date('2026-08-12T09:59:59Z'), asOf)).toBe(true);
            expect(leaseHasLapsed(new Date('2026-08-12T10:00:01Z'), asOf)).toBe(false);
        });

        it('treats an absent lease as lapsed', () => {
            // A "scanning" scan with no lease is a scan nobody answers for: that is the
            // state found after an abrupt restart, and letting it pass for alive would make
            // it unclaimable forever.
            expect(leaseHasLapsed(null, asOf)).toBe(true);
        });

        it('runs from the moment of the claim', () => {
            expect(leaseUntil(asOf).getTime() - asOf.getTime()).toBe(LEASE_MS);
        });
    });

    describe('after expiry', () => {
        it('remet en file tant qu’il reste des tentatives', () => {
            expect(afterLapse(0)).toBe('requeue');
            expect(afterLapse(MAX_ATTEMPTS - 1)).toBe('requeue');
        });

        it('fails once the attempts are exhausted', () => {
            // Otherwise a target that jams its worker every time would circulate from agent
            // to agent indefinitely.
            expect(afterLapse(MAX_ATTEMPTS)).toBe('fail');
            expect(afterLapse(MAX_ATTEMPTS + 10)).toBe('fail');
        });
    });
});
