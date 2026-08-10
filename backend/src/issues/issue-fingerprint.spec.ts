import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { FingerprintInput, buildFingerprint } from './issue-fingerprint';

interface FingerprintVector {
    label: string;
    input: FingerprintInput;
    expected: string;
}

const vectors: FingerprintVector[] = JSON.parse(readFileSync(join(__dirname, '../../test/vectors/issue-fingerprint.json'), 'utf8'));

const base: FingerprintInput = {
    repoId: 3,
    containerId: null,
    findingType: 'vulnerability',
    identifier: 'CVE-2024-1234',
    purl: 'pkg:pypi/requests@2.31.0',
    packageName: 'requests',
    filePath: 'requirements.txt'
};

describe('empreinte d’un problème', () => {
    it('dispose de vecteurs générés depuis le code Python', () => {
        expect(vectors.length).toBeGreaterThan(0);
    });

    describe.each(vectors)('$label', (vector) => {
        it("reproduit l'empreinte calculée par Python", () => {
            expect(buildFingerprint(vector.input)).toBe(vector.expected);
        });
    });

    describe('ce qui NE doit PAS changer l’empreinte', () => {
        // C'est la moitié du contrat, et la moitié qu'un portage rate : ajouter un
        // champ à l'empreinte ne casse aucun test « l'empreinte est stable », mais
        // détruit le triage à la première montée de version d'une dépendance.

        it('la version du paquet, portée par le purl, en fait partie et change donc l’empreinte', () => {
            // Nuance importante : la version est exclue en tant que *champ séparé*
            // (`Issue.package_version`), mais le purl la contient. Deux purls de
            // versions différentes donnent donc deux empreintes — et c'est bien ce que
            // fait Python. Ce test verrouille le comportement réel, pas celui que la
            // docstring pourrait laisser croire.
            const older = buildFingerprint({ ...base, purl: 'pkg:pypi/requests@2.31.0' });
            const newer = buildFingerprint({ ...base, purl: 'pkg:pypi/requests@2.32.0' });
            expect(older).not.toBe(newer);
        });

        it("le nom de paquet est ignoré quand un purl est présent", () => {
            expect(buildFingerprint({ ...base, packageName: 'tout-autre-chose' })).toBe(buildFingerprint(base));
        });

        it('les champs absents du calcul ne peuvent pas être passés', () => {
            // Le numéro de ligne et le caractère direct/transitif n'appartiennent pas
            // à `FingerprintInput` : le typage est ce qui empêche de les y glisser.
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

        it('un même identifiant sur un dépôt et sur un conteneur sont deux problèmes', () => {
            const onRepo = buildFingerprint({ ...base, repoId: 3, containerId: null });
            const onContainer = buildFingerprint({ ...base, repoId: null, containerId: 3 });
            expect(onRepo).not.toBe(onContainer);
        });
    });

    describe('valeurs limites', () => {
        it('traite null et chaîne vide comme équivalents, comme Python', () => {
            expect(buildFingerprint({ ...base, filePath: null })).toBe(buildFingerprint({ ...base, filePath: '' }));
            expect(buildFingerprint({ ...base, purl: null, packageName: 'x' })).toBe(buildFingerprint({ ...base, purl: '', packageName: 'x' }));
        });

        it("le dépôt 0 est un dépôt, pas une absence de dépôt", () => {
            // `repo_id is not None` en Python. Un test de vérité rangerait le dépôt 0
            // du côté conteneur et lui donnerait l'empreinte d'une autre cible.
            expect(buildFingerprint({ ...base, repoId: 0, containerId: 9 })).toBe(buildFingerprint({ ...base, repoId: 0, containerId: null }));
        });

        it('reste stable sur les caractères non ASCII', () => {
            const accented = buildFingerprint({ ...base, filePath: 'app/données/traitement.py' });
            expect(accented).toHaveLength(64);
            expect(accented).not.toBe(buildFingerprint({ ...base, filePath: 'app/donnees/traitement.py' }));
        });
    });

    it('rend toujours 64 caractères hexadécimaux', () => {
        for (const vector of vectors) {
            expect(vector.expected).toMatch(/^[0-9a-f]{64}$/);
        }
    });
});
