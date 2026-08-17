import { assess, distroCandidate, matchRelease, normalizePurl, packageCandidates, parseIdentifierIndex, recommendedVersion, versionParts } from './matching';

const TODAY = new Date('2026-08-13T00:00:00Z');

describe('versionParts', () => {
    it("ignores a distribution's decorated version", () => {
        // Red Hat publie « 9.7 (Plow) » : sans ce nettoyage, le cycle 9.7 ne serait
        // never recognized and the image most worth flagging would slip through.
        expect(versionParts('9.7 (Plow)')).toEqual(['9', '7']);
    });

    it('ignore le suffixe de construction d\'un paquet', () => {
        expect(versionParts('3.12.1-rc1')).toEqual(['3', '12', '1']);
        expect(versionParts('1.21.5+deb12u1')).toEqual(['1', '21', '5']);
    });

    it('rend une liste vide pour ce qui ne commence pas par un chiffre', () => {
        expect(versionParts('trixie')).toEqual([]);
        expect(versionParts('')).toEqual([]);
    });
});

describe('matchRelease', () => {
    const python = { releases: [{ name: '3.1' }, { name: '3.9' }, { name: '3.14' }] };

    it('ne range pas 3.14 dans le cycle 3.1', () => {
        // The central trap: "3.14" starts with "3.1" as a string. A `startsWith` would
        // announce a support window closed years ago on a perfectly supported version.
        expect(matchRelease(python, '3.14.0')?.name).toBe('3.14');
    });

    it('retient le cycle le plus long qui correspond', () => {
        const product = { releases: [{ name: '8' }, { name: '8.1' }] };

        expect(matchRelease(product, '8.1.27')?.name).toBe('8.1');
        expect(matchRelease(product, '8.0.3')?.name).toBe('8');
    });

    it('rend null quand aucun cycle ne correspond', () => {
        expect(matchRelease(python, '2.7.18')).toBeNull();
        expect(matchRelease({ releases: [] }, '1.0')).toBeNull();
    });
});

describe('assess', () => {
    it('classes an expired cycle as high', () => {
        // Not because something is broken today, but because nothing will be fixed
        // tomorrow.
        expect(assess({ name: '3.8', eolFrom: '2024-10-07' }, TODAY)?.severity).toBe('high');
        expect(assess({ name: '3.8', isEol: true }, TODAY)?.severity).toBe('high');
    });

    it('classes an approaching end date as medium', () => {
        expect(assess({ name: '3.9', eolFrom: '2026-10-01' }, TODAY)?.severity).toBe('medium');
    });

    it('reports nothing for a comfortably supported cycle', () => {
        // Everything reaches end of life one day: flagging a version supported for another
        // three years would teach people to filter this type out entirely.
        expect(assess({ name: '3.13', eolFrom: '2029-10-01' }, TODAY)).toBeNull();
    });

    it('honours the warning window', () => {
        const release = { name: '3.9', eolFrom: '2026-12-01' };

        expect(assess(release, TODAY, 30)).toBeNull();
        expect(assess(release, TODAY, 365)?.severity).toBe('medium');
    });

    it('reports an abandoned product with no date', () => {
        expect(assess({ name: '1.0', isMaintained: false }, TODAY)?.severity).toBe('high');
    });
});

describe('recommendedVersion', () => {
    it('returns the most recent maintained release', () => {
        const product = {
            releases: [
                { name: '3.14', isMaintained: true, isEol: false, latest: { name: '3.14.1' } },
                { name: '3.9', isMaintained: false, isEol: true }
            ]
        };

        expect(recommendedVersion(product)).toBe('3.14.1');
    });

    it('rend null quand aucune version n\'est maintenue', () => {
        expect(recommendedVersion({ releases: [{ name: '1.0', isEol: true }] })).toBeNull();
    });
});

describe('normalizePurl', () => {
    it('retire la version et les qualificatifs', () => {
        // Both sides must reduce to what names the product: a SBOM purl
        // porte l'architecture, l'identifiant du catalogue n'en porte pas.
        expect(normalizePurl('pkg:rpm/redhat/openssl@3.5.1?arch=x86_64')).toBe('pkg:rpm/redhat/openssl');
        expect(normalizePurl('pkg:generic/python@3.9.18')).toBe('pkg:generic/python');
    });

    it('leaves an already-reduced purl untouched', () => {
        expect(normalizePurl('pkg:generic/python')).toBe('pkg:generic/python');
    });
});

describe('packageCandidates', () => {
    const index = parseIdentifierIndex({
        result: [{ identifier: 'pkg:generic/python', product: { name: 'python' } }]
    });

    it('matches a SBOM package to its product', () => {
        const candidates = packageCandidates(
            { artifacts: [{ purl: 'pkg:generic/python@3.9.18', version: '3.9.18', name: 'python' }] },
            index
        );

        expect(candidates).toEqual([{ product: 'python', version: '3.9.18', label: 'python', purl: 'pkg:generic/python@3.9.18' }]);
    });

    it('discards packages with no purl or version, and those outside the catalog', () => {
        const candidates = packageCandidates(
            {
                artifacts: [
                    { purl: 'pkg:npm/lodash@4.17.21', version: '4.17.21' },
                    { version: '1.0' },
                    { purl: 'pkg:generic/python', version: '' }
                ]
            },
            index
        );

        expect(candidates).toEqual([]);
    });
});

describe('distroCandidate', () => {
    it('lit la distribution du SBOM', () => {
        // The most useful answer for an image, and the one no package lookup would find: a
        // Syft SBOM carries no purl for the operating system itself.
        expect(distroCandidate({ distro: { id: 'Debian', versionID: '11', name: 'Debian GNU/Linux' } })).toEqual({
            id: 'debian',
            version: '11',
            label: 'Debian GNU/Linux'
        });
    });

    it('rend null pour un SBOM sans bloc distro exploitable', () => {
        expect(distroCandidate({})).toBeNull();
        expect(distroCandidate({ distro: { id: 'alpine' } })).toBeNull();
    });
});
