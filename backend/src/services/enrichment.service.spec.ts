import { EPSS_API_URL, KEV_CATALOG_URL } from '../domain/enrichment/catalogs';
import { Finding } from '../persistence/entities';
import { EnrichmentService } from './enrichment.service';
import type { SettingsService } from './settings.service';

/** Un service de réglages qui répond ce qu'on lui dit, sans base. */
function settings(enabled: boolean): SettingsService {
    return { isEnabled: async () => enabled } as unknown as SettingsService;
}

function finding(values: Partial<Finding>): Finding {
    return Object.assign(new Finding(), { type: 'vulnerability', isKev: false, epssScore: null }, values);
}

/** Un réseau simulé qui enregistre ce qu'on lui demande. */
function network(responses: Record<string, unknown>) {
    const calls: string[] = [];
    const fetchJson = async (url: string) => {
        calls.push(url);
        const key = Object.keys(responses).find((prefix) => url.startsWith(prefix));
        if (!key) throw new Error(`URL inattendue : ${url}`);
        const response = responses[key];
        if (response instanceof Error) throw response;
        return response;
    };
    return { calls, fetchJson };
}

describe('EnrichmentService', () => {
    const epss = { data: [{ cve: 'CVE-2021-44228', epss: '0.975' }] };
    const kev = { vulnerabilities: [{ cveID: 'CVE-2021-44228' }] };

    it('pose le score EPSS et le drapeau KEV sur les vulnérabilités', async () => {
        const { fetchJson } = network({ [EPSS_API_URL]: epss, [KEV_CATALOG_URL]: kev });
        const findings = [finding({ identifier: 'CVE-2021-44228' }), finding({ identifier: 'CVE-2020-0000' })];

        await new EnrichmentService(settings(true), fetchJson).enrich(findings);

        expect(findings[0].epssScore).toBe(0.975);
        expect(findings[0].isKev).toBe(true);
        // Non trouvé aux deux catalogues : pas de score, et **explicitement** pas KEV.
        expect(findings[1].epssScore).toBeNull();
        expect(findings[1].isKev).toBe(false);
    });

    it("n'appelle pas le réseau quand le réglage est désactivé", async () => {
        const { calls, fetchJson } = network({});
        const findings = [finding({ identifier: 'CVE-2021-44228' })];

        await new EnrichmentService(settings(false), fetchJson).enrich(findings);

        expect(calls).toEqual([]);
        expect(findings[0].isKev).toBe(false);
    });

    it("n'interroge que les vulnérabilités, jamais les secrets ni le code", async () => {
        // Ce qui part sur le réseau est le point sensible du service : un identifiant de
        // règle Semgrep ou un chemin de fichier envoyé à une API publique serait une fuite.
        const { calls, fetchJson } = network({ [EPSS_API_URL]: epss, [KEV_CATALOG_URL]: kev });

        await new EnrichmentService(settings(true), fetchJson).enrich([
            finding({ type: 'secret', identifier: 'aws-access-token', filePath: 'src/config.py' }),
            finding({ type: 'sast', identifier: 'zanshin.python.dangerous-eval' })
        ]);

        expect(calls).toEqual([]);
    });

    it('laisse les constats intacts quand les deux appels échouent', async () => {
        const { fetchJson } = network({ [EPSS_API_URL]: new Error('502'), [KEV_CATALOG_URL]: new Error('délai dépassé') });
        const findings = [finding({ identifier: 'CVE-2021-44228', epssScore: 0.5 })];

        await expect(new EnrichmentService(settings(true), fetchJson).enrich(findings)).resolves.toBeUndefined();

        // Le score du scan précédent survit : l'écraser par `null` transformerait une panne
        // réseau en perte de données.
        expect(findings[0].epssScore).toBe(0.5);
    });

    it('ne retient pas un catalogue KEV vide', async () => {
        // Un catalogue vide n'est jamais légitime. Le mettre en cache marquerait toutes les
        // vulnérabilités comme non exploitées pendant vingt-quatre heures.
        const responses: Record<string, unknown> = { [EPSS_API_URL]: epss, [KEV_CATALOG_URL]: { vulnerabilities: [] } };
        const { fetchJson } = network(responses);
        const service = new EnrichmentService(settings(true), fetchJson);

        await service.enrich([finding({ identifier: 'CVE-2021-44228' })]);
        responses[KEV_CATALOG_URL] = kev;

        const second = [finding({ identifier: 'CVE-2021-44228' })];
        await service.enrich(second);

        expect(second[0].isKev).toBe(true);
    });

    it('met le catalogue KEV en cache entre deux scans', async () => {
        const { calls, fetchJson } = network({ [EPSS_API_URL]: epss, [KEV_CATALOG_URL]: kev });
        const service = new EnrichmentService(settings(true), fetchJson);

        await service.enrich([finding({ identifier: 'CVE-2021-44228' })]);
        await service.enrich([finding({ identifier: 'CVE-2021-44228' })]);

        expect(calls.filter((url) => url.startsWith(KEV_CATALOG_URL))).toHaveLength(1);
        expect(calls.filter((url) => url.startsWith(EPSS_API_URL))).toHaveLength(2);
    });

    it('découpe les interrogations EPSS en lots', async () => {
        const { calls, fetchJson } = network({ [EPSS_API_URL]: { data: [] }, [KEV_CATALOG_URL]: kev });
        const findings = Array.from({ length: 200 }, (_, index) => finding({ identifier: `CVE-2024-${index}` }));

        await new EnrichmentService(settings(true), fetchJson).enrich(findings);

        expect(calls.filter((url) => url.startsWith(EPSS_API_URL))).toHaveLength(3);
    });
});
