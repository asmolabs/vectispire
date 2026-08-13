import { Scan } from '../persistence/entities';
import { EolService } from './eol.service';
import type { SettingsService } from './settings.service';

/** Des réglages en mémoire, sans base. */
function settings(values: Record<string, string> = {}): SettingsService {
    return {
        get: async (key: string, fallback = '') => values[key] ?? fallback,
        isEnabled: async (key: string, fallback: boolean) => (values[key] ?? (fallback ? 'true' : 'false')) === 'true'
    } as unknown as SettingsService;
}

function scan(): Scan {
    return Object.assign(new Scan(), { id: 7, repoId: 1, containerId: null });
}

/** Le catalogue endoflife.date, simulé. Une URL inconnue rend `null`, comme un 404. */
function catalogue(products: Record<string, unknown>, index: unknown[] = []) {
    const calls: string[] = [];
    const fetchJson = async (url: string) => {
        calls.push(url);
        if (url.includes('/identifiers/purl/')) return { result: index };
        const name = /\/products\/([^/]+)\//.exec(url)?.[1];
        const product = name ? products[decodeURIComponent(name)] : undefined;
        if (product === undefined) return null;
        if (product instanceof Error) throw product;
        return { result: product };
    };
    return { calls, fetchJson };
}

const DEBIAN = {
    releases: [
        { name: '11', eolFrom: '2024-08-14', isEol: true, isMaintained: false },
        { name: '12', eolFrom: '2028-06-10', isMaintained: true, isEol: false, latest: { name: '12.7' } }
    ]
};

describe('EolService', () => {
    it("signale la distribution d'une image échue", async () => {
        // Le cas qui motive tout le service : une image bâtie sur une base échue rendait
        // le même bulletin de santé qu'une image supportée.
        const { fetchJson } = catalogue({ debian: DEBIAN });
        const findings = await new EolService(settings(), fetchJson).buildFindings(scan(), {
            distro: { id: 'debian', versionID: '11', name: 'Debian GNU/Linux' }
        });

        expect(findings).toHaveLength(1);
        expect(findings[0].severity).toBe('high');
        expect(findings[0].identifier).toBe('EOL-debian-11');
        // « Corriger » veut dire : passer à la version maintenue.
        expect(findings[0].fixVersions).toBe('12.7');
        expect(findings[0].fixState).toBe('fixed');
        expect(findings[0].link).toBe('https://endoflife.date/debian');
    });

    it('ne signale pas une distribution supportée', async () => {
        const { fetchJson } = catalogue({ debian: DEBIAN });
        const findings = await new EolService(settings(), fetchJson).buildFindings(scan(), {
            distro: { id: 'debian', versionID: '12', name: 'Debian' }
        });

        expect(findings).toEqual([]);
    });

    it('dédoublonne sur le cycle et non sur la version', async () => {
        // Une image liste souvent le même environnement comme distribution *et* comme
        // paquet, en « 3.9 » et « 3.9.18 » : le constat porte sur le cycle dans les deux
        // cas, et le compter deux fois gonflerait le backlog sans rien apprendre.
        const python = { releases: [{ name: '3.9', eolFrom: '2025-10-31', isEol: true }] };
        const { fetchJson } = catalogue({ python }, [{ identifier: 'pkg:generic/python', product: { name: 'python' } }]);

        const findings = await new EolService(settings(), fetchJson).buildFindings(scan(), {
            distro: { id: 'python', versionID: '3.9' },
            artifacts: [{ purl: 'pkg:generic/python@3.9.18', version: '3.9.18', name: 'python' }]
        });

        expect(findings).toHaveLength(1);
        // L'identifiant porte le cycle, pas le correctif : c'est ce qui préserve le triage
        // quand la version de correctif bouge d'un scan à l'autre.
        expect(findings[0].identifier).toBe('EOL-python-3.9');
    });

    it('ne rend rien quand le réglage est désactivé, sans appeler le réseau', async () => {
        const { calls, fetchJson } = catalogue({ debian: DEBIAN });

        const findings = await new EolService(settings({ eol_detection_enabled: 'false' }), fetchJson).buildFindings(scan(), {
            distro: { id: 'debian', versionID: '11' }
        });

        expect(findings).toEqual([]);
        expect(calls).toEqual([]);
    });

    it('honore la fenêtre d\'avertissement réglée', async () => {
        const soon = { releases: [{ name: '1', eolFrom: futureDate(60) }] };
        const { fetchJson } = catalogue({ produit: soon });
        const sbom = { distro: { id: 'produit', versionID: '1' } };

        expect(await new EolService(settings({ eol_warn_days: '30' }), fetchJson).buildFindings(scan(), sbom)).toEqual([]);
        expect(await new EolService(settings({ eol_warn_days: '90' }), fetchJson).buildFindings(scan(), sbom)).toHaveLength(1);
    });

    it('rend une liste vide sans SBOM plutôt que de lever', async () => {
        const { calls, fetchJson } = catalogue({});

        expect(await new EolService(settings(), fetchJson).buildFindings(scan(), null)).toEqual([]);
        expect(calls).toEqual([]);
    });

    it('garde les cycles déjà appariés quand une consultation échoue', async () => {
        // Un produit injoignable ne doit pas faire perdre le reste : un résultat partiel
        // vaut mieux qu'aucun, et le manquant sera revu au scan suivant.
        const python = { releases: [{ name: '3.9', isEol: true }] };
        const { fetchJson } = catalogue({ python, casse: new Error('502') }, [
            { identifier: 'pkg:generic/python', product: { name: 'python' } },
            { identifier: 'pkg:generic/casse', product: { name: 'casse' } }
        ]);

        const findings = await new EolService(settings(), fetchJson).buildFindings(scan(), {
            artifacts: [
                { purl: 'pkg:generic/casse@1.0', version: '1.0', name: 'casse' },
                { purl: 'pkg:generic/python@3.9.18', version: '3.9.18', name: 'python' }
            ]
        });

        expect(findings.map((finding) => finding.identifier)).toEqual(['EOL-python-3.9']);
    });

    it('met le catalogue en cache entre deux scans', async () => {
        const { calls, fetchJson } = catalogue({ debian: DEBIAN });
        const service = new EolService(settings(), fetchJson);
        const sbom = { distro: { id: 'debian', versionID: '11' } };

        await service.buildFindings(scan(), sbom);
        await service.buildFindings(scan(), sbom);

        expect(calls.filter((url) => url.includes('/products/debian/'))).toHaveLength(1);
    });

    it('donne une phrase au constat', async () => {
        const { fetchJson } = catalogue({ debian: DEBIAN });
        const service = new EolService(settings(), fetchJson);
        const [finding] = await service.buildFindings(scan(), { distro: { id: 'debian', versionID: '11', name: 'Debian' } });

        // Sans elle, l'écran n'afficherait qu'un identifiant : `Finding.description` n'est
        // pas alimentée pour ce type, la phrase passe par la carte des descriptions.
        expect(service.describe(finding)).toContain('Debian 11');
        expect(service.describe(finding)).toContain('Aucun correctif');
    });
});

function futureDate(days: number): string {
    return new Date(Date.now() + days * 86_400_000).toISOString().slice(0, 10);
}
