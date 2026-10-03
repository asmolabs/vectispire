import { describe, expect, it } from 'vitest';
import { caPemProblem, expiryState, forgeConflict, isCloudAddress } from './forge-words';

const CERT = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----';

/** The readings the forge screens share: a pasted CA's shape, a cloud address, an expiry, a 409's cause. */
describe('the forge words', () => {
    it("reads a pasted CA's shape, and leaves the rest to the server", () => {
        expect(caPemProblem('')).toBeNull();
        expect(caPemProblem(CERT)).toBeNull();
        expect(caPemProblem(Array.from({ length: 8 }, () => CERT).join('\n'))).toBeNull();
        expect(caPemProblem(Array.from({ length: 9 }, () => CERT).join('\n'))).toBe('too_many');
        expect(caPemProblem('-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----')).toBe('private_key'); // gitleaks:allow
        expect(caPemProblem('hello')).toBe('not_pem');
        expect(caPemProblem('-----BEGIN CERTIFICATE-----\nMIIB')).toBe('unbalanced');
    });

    it('knows the cloud addresses, for which neither the internal network nor a CA applies', () => {
        expect(isCloudAddress('')).toBe(true);
        expect(isCloudAddress('https://gitlab.com')).toBe(true);
        expect(isCloudAddress('https://github.com/')).toBe(true);
        expect(isCloudAddress('https://acme.ghe.com')).toBe(true);
        expect(isCloudAddress('https://gitlab.example.internal')).toBe(false);
        expect(isCloudAddress('https://notgitlab.com')).toBe(false);
        expect(isCloudAddress('not a url')).toBe(false);
    });

    it('announces an expiry fourteen days ahead', () => {
        const now = new Date('2026-10-03T00:00:00Z');
        expect(expiryState(null, now)).toBe('none');
        expect(expiryState('2026-10-17T00:00:00Z', now)).toBe('soon');
        expect(expiryState('2026-10-17T00:00:01Z', now)).toBe('valid');
        expect(expiryState('2026-10-02T23:59:59Z', now)).toBe('expired');
    });

    it("reads a 409's cause from the problem's type, never from its sentence", () => {
        const conflict = (error: object, status = 409) => forgeConflict({ status, error });
        expect(
            conflict({ type: 'urn:vectispire:problem:forge-discovery-in-progress', discoveryId: 13, detail: 'x' })
        ).toEqual({ cause: 'forge-discovery-in-progress', discoveryId: 13, latestDiscoveryId: null, state: null });
        expect(
            conflict({ type: 'urn:vectispire:problem:forge-discovery-superseded', latestDiscoveryId: 14 })?.cause
        ).toBe('forge-discovery-superseded');
        expect(conflict({ type: 'about:blank', detail: 'forge-discovery-in-progress' })).toBeNull();
        expect(conflict({ type: 'urn:vectispire:problem:forge-discovery-in-progress' }, 400)).toBeNull();
    });
});
