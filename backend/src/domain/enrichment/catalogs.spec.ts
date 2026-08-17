import { batches, parseEpssResponse, parseKevCatalog } from './catalogs';

describe('parseEpssResponse', () => {
    it('reads the scores returned as strings, as the API actually does', () => {
        // The central trap: FIRST returns "0.00042" and not 0.00042. Taking it as is would
        // store text in a numeric column.
        const scores = parseEpssResponse({ data: [{ cve: 'CVE-2021-44228', epss: '0.97512', percentile: '0.99' }] });

        expect(scores.get('CVE-2021-44228')).toBe(0.97512);
    });

    it('discards unusable entries without losing the others', () => {
        const scores = parseEpssResponse({
            data: [{ cve: 'CVE-1', epss: 'pas-un-nombre' }, { epss: '0.5' }, { cve: 'CVE-2', epss: null }, { cve: 'CVE-3', epss: '0.25' }]
        });

        expect([...scores]).toEqual([['CVE-3', 0.25]]);
    });

    it('does not convert an absent value into a score of zero', () => {
        // `Number(null)` and `Number('')` are 0, which is a legitimate EPSS score: without
        // a guard, an absent field would read as "zero probability of exploitation".
        const scores = parseEpssResponse({ data: [{ cve: 'CVE-1', epss: null }, { cve: 'CVE-2', epss: '' }, { cve: 'CVE-3', epss: '0' }] });

        expect(scores.has('CVE-1')).toBe(false);
        expect(scores.has('CVE-2')).toBe(false);
        // A genuinely published zero, on the other hand, is kept.
        expect(scores.get('CVE-3')).toBe(0);
    });

    it('returns an empty map for an unreadable payload rather than throwing', () => {
        // Enrichment is optional: an exception here would fail a scan that otherwise
        // produced real results.
        expect(parseEpssResponse(null).size).toBe(0);
        expect(parseEpssResponse({ data: 'inattendu' }).size).toBe(0);
        expect(parseEpssResponse({ error: 'quota exceeded' }).size).toBe(0);
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
    it('splits without losing or duplicating anything', () => {
        const items = Array.from({ length: 205 }, (_, index) => `CVE-${index}`);
        const lots = batches(items);

        expect(lots.map((lot) => lot.length)).toEqual([90, 90, 25]);
        expect(lots.flat()).toEqual(items);
    });

    it('returns an empty list for an empty input', () => {
        expect(batches([])).toEqual([]);
    });
});
