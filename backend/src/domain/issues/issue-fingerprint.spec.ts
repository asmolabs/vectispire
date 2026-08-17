import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { FingerprintInput, buildFingerprint } from './issue-fingerprint';

interface FingerprintVector {
    label: string;
    input: FingerprintInput;
    expected: string;
}

const vectors: FingerprintVector[] = JSON.parse(readFileSync(join(__dirname, '../../../test/vectors/issue-fingerprint.json'), 'utf8'));

const base: FingerprintInput = {
    repoId: 3,
    containerId: null,
    findingType: 'vulnerability',
    identifier: 'CVE-2024-1234',
    purl: 'pkg:pypi/requests@2.31.0',
    packageName: 'requests',
    filePath: 'requirements.txt'
};

describe("an issue's fingerprint", () => {
    it('has vectors generated from the Python code', () => {
        expect(vectors.length).toBeGreaterThan(0);
    });

    describe.each(vectors)('$label', (vector) => {
        it("reproduces the fingerprint Python computed", () => {
            expect(buildFingerprint(vector.input)).toBe(vector.expected);
        });
    });

    describe('ce qui NE doit PAS changer l’empreinte', () => {
        // This is half the contract, and the half a port gets wrong: adding a field to the
        // fingerprint breaks no "the fingerprint is stable" test, but destroys the triage at
        // the first dependency version bump.

        it('the package version, carried by the purl, is part of it and so changes the fingerprint', () => {
            // An important nuance: the version is excluded as a *separate field*
            // (`Issue.package_version`), mais le purl la contient. Deux purls de
            // different versions therefore give two fingerprints — and that is indeed what
            // Python does. This test locks the real behaviour, not the one the
            // docstring pourrait laisser croire.
            const older = buildFingerprint({ ...base, purl: 'pkg:pypi/requests@2.31.0' });
            const newer = buildFingerprint({ ...base, purl: 'pkg:pypi/requests@2.32.0' });
            expect(older).not.toBe(newer);
        });

        it("the package name is ignored when a purl is present", () => {
            expect(buildFingerprint({ ...base, packageName: 'tout-autre-chose' })).toBe(buildFingerprint(base));
        });

        it('the fields absent from the calculation cannot be passed', () => {
            // The line number and the direct/transitive flag do not belong to
            // `FingerprintInput`: the typing is what stops anyone slipping them in.
            const keys = Object.keys(base).sort();
            expect(keys).toEqual(['containerId', 'filePath', 'findingType', 'identifier', 'packageName', 'purl', 'repoId']);
        });
    });

    describe('ce qui DOIT changer l’empreinte', () => {
        it.each([
            ['la cible', { repoId: 4 }],
            ['le type de constat', { findingType: 'secret' }],
            ["l'identifiant", { identifier: 'CVE-2024-9999' }],
            ['le purl', { purl: 'pkg:pypi/urllib3@2.0.0' }],
            ['le chemin', { filePath: 'autre.txt' }]
        ] as [string, Partial<FingerprintInput>][])('%s', (_label, override) => {
            expect(buildFingerprint({ ...base, ...override })).not.toBe(buildFingerprint(base));
        });

        it('the same identifier on a repository and on a container are two issues', () => {
            const onRepo = buildFingerprint({ ...base, repoId: 3, containerId: null });
            const onContainer = buildFingerprint({ ...base, repoId: null, containerId: 3 });
            expect(onRepo).not.toBe(onContainer);
        });
    });

    describe('valeurs limites', () => {
        it('treats null and the empty string as equivalent, as Python does', () => {
            expect(buildFingerprint({ ...base, filePath: null })).toBe(buildFingerprint({ ...base, filePath: '' }));
            expect(buildFingerprint({ ...base, purl: null, packageName: 'x' })).toBe(buildFingerprint({ ...base, purl: '', packageName: 'x' }));
        });

        it("repository 0 is a repository, not the absence of one", () => {
            // `repo_id is not None` in Python. A truthiness test would file repository 0 on
            // the container side and give it another target's fingerprint.
            expect(buildFingerprint({ ...base, repoId: 0, containerId: 9 })).toBe(buildFingerprint({ ...base, repoId: 0, containerId: null }));
        });

        it('stays stable on non-ASCII characters', () => {
            // The accented path is kept on purpose: it is the input this test exists for.
            const accented = buildFingerprint({ ...base, filePath: 'app/données/traitement.py' });
            expect(accented).toHaveLength(64);
            expect(accented).not.toBe(buildFingerprint({ ...base, filePath: 'app/donnees/traitement.py' }));
        });
    });

    it('always returns 64 hexadecimal characters', () => {
        for (const vector of vectors) {
            expect(vector.expected).toMatch(/^[0-9a-f]{64}$/);
        }
    });
});
