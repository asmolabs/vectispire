import { assess, distroCandidate, matchRelease, normalizePurl, packageCandidates, parseIdentifierIndex, recommendedVersion, versionParts } from './matching';

const TODAY = new Date('2026-08-13T00:00:00Z');

describe('versionParts', () => {
    it('ignore la version décorée d\'une distribution', () => {
        // Red Hat publie « 9.7 (Plow) » : sans ce nettoyage, le cycle 9.7 ne serait
        // jamais reconnu et l'image la plus intéressante à signaler passerait au travers.
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
        // Le piège central : « 3.14 » commence par « 3.1 » en tant que chaîne. Un
        // `startsWith` annoncerait une fin de support passée depuis des années sur une
        // version parfaitement supportée.
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
    it('classe un cycle échu en high', () => {
        // Non parce que quelque chose est cassé aujourd'hui, mais parce que rien ne sera
        // corrigé demain.
        expect(assess({ name: '3.8', eolFrom: '2024-10-07' }, TODAY)?.severity).toBe('high');
        expect(assess({ name: '3.8', isEol: true }, TODAY)?.severity).toBe('high');
    });

    it('classe une échéance proche en medium', () => {
        expect(assess({ name: '3.9', eolFrom: '2026-10-01' }, TODAY)?.severity).toBe('medium');
    });

    it('ne signale rien pour un cycle confortablement supporté', () => {
        // Tout a une fin de vie un jour : signaler une version supportée encore trois ans
        // apprendrait aux gens à filtrer ce type entièrement.
        expect(assess({ name: '3.13', eolFrom: '2029-10-01' }, TODAY)).toBeNull();
    });

    it('honore la fenêtre d\'avertissement', () => {
        const release = { name: '3.9', eolFrom: '2026-12-01' };

        expect(assess(release, TODAY, 30)).toBeNull();
        expect(assess(release, TODAY, 365)?.severity).toBe('medium');
    });

    it('signale un produit abandonné sans date', () => {
        expect(assess({ name: '1.0', isMaintained: false }, TODAY)?.severity).toBe('high');
    });
});

describe('recommendedVersion', () => {
    it('rend la version maintenue la plus récente', () => {
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
        // Les deux côtés doivent se réduire à ce qui désigne le produit : un purl de SBOM
        // porte l'architecture, l'identifiant du catalogue n'en porte pas.
        expect(normalizePurl('pkg:rpm/redhat/openssl@3.5.1?arch=x86_64')).toBe('pkg:rpm/redhat/openssl');
        expect(normalizePurl('pkg:generic/python@3.9.18')).toBe('pkg:generic/python');
    });

    it('laisse intact un purl déjà réduit', () => {
        expect(normalizePurl('pkg:generic/python')).toBe('pkg:generic/python');
    });
});

describe('packageCandidates', () => {
    const index = parseIdentifierIndex({
        result: [{ identifier: 'pkg:generic/python', product: { name: 'python' } }]
    });

    it('apparie un paquet du SBOM à son produit', () => {
        const candidates = packageCandidates(
            { artifacts: [{ purl: 'pkg:generic/python@3.9.18', version: '3.9.18', name: 'python' }] },
            index
        );

        expect(candidates).toEqual([{ product: 'python', version: '3.9.18', label: 'python', purl: 'pkg:generic/python@3.9.18' }]);
    });

    it('écarte les paquets sans purl ni version, et ceux hors catalogue', () => {
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
        // La réponse la plus utile pour une image, et celle qu'aucune recherche par paquet
        // ne trouverait : un SBOM Syft ne porte aucun purl pour le système lui-même.
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
