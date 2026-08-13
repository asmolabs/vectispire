import type { TicketableIssue } from '../domain/tickets/ticket';
import { EncryptionService } from './encryption.service';
import { TOKEN_CONTEXT, TicketService } from './ticket.service';
import type { SettingsService } from './settings.service';

/** Des réglages en mémoire, avec écriture, sans base. */
function settings(values: Record<string, string> = {}): SettingsService {
    const store = { ...values };
    return {
        get: async (key: string, fallback = '') => store[key] ?? fallback,
        set: async (key: string, value: string) => {
            store[key] = value;
        },
        isEnabled: async (key: string, fallback: boolean) => (store[key] ?? (fallback ? 'true' : 'false')) === 'true',
        all: async () => ({ ...store })
    } as unknown as SettingsService;
}

const CONFIGURED = {
    ticket_provider: 'gitlab',
    ticket_base_url: 'https://gitlab.exemple.test/',
    ticket_project: 'groupe/projet',
    ticket_token: 'jeton-en-clair'
};

function issue(values: Partial<TicketableIssue> = {}): TicketableIssue {
    return {
        id: 1,
        type: 'vulnerability',
        identifier: 'CVE-2021-44228',
        severity: 'critical',
        packageName: 'log4j-core',
        packageVersion: '2.14.1',
        fixVersions: '2.17.1',
        fixState: null,
        isDirectDependency: null,
        filePath: null,
        line: null,
        isKev: false,
        epssScore: null,
        link: null,
        description: null,
        fingerprint: 'abc',
        ...values
    };
}

/** Un gestionnaire simulé, qui enregistre ce qu'on lui envoie. */
function tracker(response: Record<string, unknown> = { iid: 42, web_url: 'https://gitlab.exemple.test/groupe/projet/-/issues/42' }) {
    const calls: { url: string; body: unknown; headers: Record<string, string> }[] = [];
    const post = async (url: string, body: unknown, headers: Record<string, string>) => {
        calls.push({ url, body, headers });
        if (response instanceof Error) throw response;
        return response;
    };
    return { calls, post };
}

describe('TicketService', () => {
    it('ouvre un ticket GitLab et rend sa référence', async () => {
        const { calls, post } = tracker();
        const ticket = await new TicketService(settings(CONFIGURED), null, post).createForIssue(issue(), 'org/projet');

        expect(ticket).toEqual({ reference: '#42', url: 'https://gitlab.exemple.test/groupe/projet/-/issues/42' });
        // Le chemin de projet est encodé : « groupe/projet » est la forme sous laquelle la
        // plupart des gens l'ont, et l'envoyer brut casserait l'URL.
        expect(calls[0].url).toBe('https://gitlab.exemple.test/api/v4/projects/groupe%2Fprojet/issues');
        expect(calls[0].headers['PRIVATE-TOKEN']).toBe('jeton-en-clair');
    });

    it('envoie à Jira une description au format Atlassian', async () => {
        // L'API v3 de Jira Cloud refuse une chaîne simple pour `description` : lui en
        // envoyer une donnerait un 400 que rien dans le message ne rattacherait au format.
        const { calls, post } = tracker({ key: 'SEC-7' });
        const jira = new TicketService(
            settings({ ...CONFIGURED, ticket_provider: 'jira', ticket_base_url: 'https://exemple.atlassian.net' }),
            null,
            post
        );

        const ticket = await jira.createForIssue(issue(), 'org/projet');

        expect(ticket).toEqual({ reference: 'SEC-7', url: 'https://exemple.atlassian.net/browse/SEC-7' });
        const fields = (calls[0].body as { fields: { description: { type: string; content: unknown[] } } }).fields;
        expect(fields.description.type).toBe('doc');
        expect(fields.description.content.length).toBeGreaterThan(0);
    });

    it("n'ouvre rien tant que la configuration est incomplète", async () => {
        const { calls, post } = tracker();

        for (const missing of ['ticket_provider', 'ticket_base_url', 'ticket_project', 'ticket_token']) {
            const partial = { ...CONFIGURED, [missing]: '' };
            expect(await new TicketService(settings(partial), null, post).createForIssue(issue(), 'cible')).toBeNull();
        }
        expect(calls).toEqual([]);
    });

    it('refuse une URL de base qui pointe vers les métadonnées d\'instance', async () => {
        // Le réglage autorise le privé par défaut — un GitLab auto-hébergé est courant —
        // mais la plage des métadonnées reste refusée quoi qu'il arrive.
        const { calls, post } = tracker();
        const service = new TicketService(settings({ ...CONFIGURED, ticket_base_url: 'http://169.254.169.254' }), null, post);

        expect(await service.createForIssue(issue(), 'cible')).toBeNull();
        expect(calls).toEqual([]);
    });

    it('accepte un gestionnaire sur le réseau interne', async () => {
        const { post } = tracker();
        const service = new TicketService(settings({ ...CONFIGURED, ticket_base_url: 'http://192.168.1.10' }), null, post);

        expect(await service.createForIssue(issue(), 'cible')).not.toBeNull();
    });

    it('rend null au lieu de lever quand le gestionnaire refuse', async () => {
        // Ceci tourne depuis le tour d'entretien : une exception emporterait la purge et
        // l'expiration des triages avec elle.
        const post = async () => {
            throw new Error('HTTP 503');
        };
        const service = new TicketService(settings(CONFIGURED), null, post);

        await expect(service.createForIssue(issue(), 'cible')).resolves.toBeNull();
    });

    it('chiffre le jeton au repos et le relit', async () => {
        const encryption = new EncryptionService('BxVsND4oQncTvWqIgwrW1+gpVJ38F3JPEM/UeZjVuCs=');
        const store = settings({ ...CONFIGURED, ticket_token: '' });
        const service = new TicketService(store, encryption, tracker().post);

        await service.setToken('glpat-secret');

        // Ce qui dort en base n'est pas le jeton.
        expect((await store.all()).ticket_token).not.toContain('glpat-secret');
        expect(await service.token()).toBe('glpat-secret');
    });

    it('désactive les tickets plutôt que de lever quand le jeton est indéchiffrable', async () => {
        // Une clé de chiffrement tournée ne doit pas casser le tour d'entretien.
        const encryption = new EncryptionService('BxVsND4oQncTvWqIgwrW1+gpVJ38F3JPEM/UeZjVuCs=');
        const autre = new EncryptionService('a29UZ8pQ2yUqk1yQ0wG5vQ2p8i5rN3xO0lE7cV6bJhE=');
        const store = settings({ ...CONFIGURED, ticket_token: encryption.encrypt('glpat-secret', TOKEN_CONTEXT) });

        const service = new TicketService(store, autre, tracker().post);

        expect(await service.token()).toBe('');
        expect(await service.isEnabled()).toBe(false);
    });
});
