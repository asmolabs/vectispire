import { batches, parseEpssResponse, parseKevCatalog } from './catalogs';

describe('parseEpssResponse', () => {
    it('lit les scores rendus en chaîne, comme le fait réellement l\'API', () => {
        // Le piège central : FIRST rend « 0.00042 » et non 0.00042. Le prendre tel quel
        // stockerait du texte dans une colonne numérique.
        const scores = parseEpssResponse({ data: [{ cve: 'CVE-2021-44228', epss: '0.97512', percentile: '0.99' }] });

        expect(scores.get('CVE-2021-44228')).toBe(0.97512);
    });

    it('écarte les entrées inexploitables sans perdre les autres', () => {
        const scores = parseEpssResponse({
            data: [{ cve: 'CVE-1', epss: 'pas-un-nombre' }, { epss: '0.5' }, { cve: 'CVE-2', epss: null }, { cve: 'CVE-3', epss: '0.25' }]
        });

        expect([...scores]).toEqual([['CVE-3', 0.25]]);
    });

    it('ne convertit pas une valeur absente en score de zéro', () => {
        // `Number(null)` et `Number('')` valent 0, qui est un score EPSS légitime : sans
        // garde, un champ absent se lirait « probabilité d'exploitation nulle ».
        const scores = parseEpssResponse({ data: [{ cve: 'CVE-1', epss: null }, { cve: 'CVE-2', epss: '' }, { cve: 'CVE-3', epss: '0' }] });

        expect(scores.has('CVE-1')).toBe(false);
        expect(scores.has('CVE-2')).toBe(false);
        // Un zéro réellement publié, lui, est retenu.
        expect(scores.get('CVE-3')).toBe(0);
    });

    it('rend une carte vide sur une charge illisible plutôt que de lever', () => {
        // L'enrichissement est facultatif : une exception ici ferait échouer un scan qui
        // a par ailleurs produit de vrais résultats.
        expect(parseEpssResponse(null).size).toBe(0);
        expect(parseEpssResponse({ data: 'inattendu' }).size).toBe(0);
        expect(parseEpssResponse({ erreur: 'quota dépassé' }).size).toBe(0);
    });
});

describe('parseKevCatalog', () => {
    it('rend les identifiants du catalogue', () => {
        const kev = parseKevCatalog({
            vulnerabilities: [{ cveID: 'CVE-2021-44228', vendorProject: 'Apache' }, { cveID: 'CVE-2017-5638' }]
        });

        expect(kev).toEqual(new Set(['CVE-2021-44228', 'CVE-2017-5638']));
    });

    it('rend un ensemble vide sur une charge illisible', () => {
        expect(parseKevCatalog({}).size).toBe(0);
        expect(parseKevCatalog(undefined).size).toBe(0);
    });
});

describe('batches', () => {
    it('découpe sans rien perdre ni dupliquer', () => {
        const items = Array.from({ length: 205 }, (_, index) => `CVE-${index}`);
        const lots = batches(items);

        expect(lots.map((lot) => lot.length)).toEqual([90, 90, 25]);
        expect(lots.flat()).toEqual(items);
    });

    it('rend une liste vide pour une entrée vide', () => {
        expect(batches([])).toEqual([]);
    });
});
