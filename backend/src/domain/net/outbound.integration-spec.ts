import { createServer, type Server } from 'node:http';
import { outboundFetch, outboundJson } from './outbound';

/**
 * Le refus des redirections, contre de vrais serveurs.
 *
 * **Ce comportement ne se simule pas.** Il est décidé par le client HTTP de Node, pas par du
 * code de ce dépôt : un faux `fetch` prouverait seulement que le faux fait ce qu'on lui a
 * dit. Deux serveurs suffisent — l'un redirige, l'autre joue la destination interne que le
 * garde d'URL aurait refusée.
 *
 * Ce que ces tests protègent : `validateOutboundUrl` ne vérifie que la **première** requête.
 * Node suit les redirections par défaut, si bien qu'une destination validée répondant
 * `302 Location: http://169.254.169.254/` était suivie sans que rien ne revérifie. Le cas le
 * plus coûteux est la revue par modèle, dont le garde exige une destination interne
 * précisément parce qu'elle reçoit le code source du dépôt scanné.
 */
describe('appel sortant', () => {
    let interne: Server;
    let redirecteur: Server;
    let atteint = false;

    /** Démarre un serveur sur un port libre et rend ce port. */
    function listen(server: Server): Promise<number> {
        return new Promise((resolve) => server.listen(0, () => resolve((server.address() as { port: number }).port)));
    }

    beforeAll(async () => {
        interne = createServer((_request, response) => {
            atteint = true;
            response.writeHead(200, { 'content-type': 'application/json' });
            response.end('{"secret":"atteint"}');
        });
        const portInterne = await listen(interne);

        redirecteur = createServer((request, response) => {
            if (request.url === '/redirige') {
                response.writeHead(302, { Location: `http://127.0.0.1:${portInterne}/interne` });
                return response.end();
            }
            response.writeHead(200, { 'content-type': 'application/json' });
            response.end('{"ok":true}');
        });
        await listen(redirecteur);
    });

    afterAll(() => {
        interne.close();
        redirecteur.close();
    });

    beforeEach(() => {
        atteint = false;
    });

    const url = (chemin: string) => `http://127.0.0.1:${(redirecteur.address() as { port: number }).port}${chemin}`;

    it('refuse de suivre une redirection, et n’atteint pas la cible', async () => {
        await expect(outboundFetch(url('/redirige'), { method: 'POST', body: {}, timeoutMs: 5_000 })).rejects.toThrow();

        // **L'assertion qui compte.** Une exception seule ne prouverait pas grand-chose : ce
        // qui importe est que la destination interne n'ait rien reçu.
        expect(atteint).toBe(false);
    });

    it('refuse aussi sur un GET JSON', async () => {
        await expect(outboundJson(url('/redirige'), { timeoutMs: 5_000 })).rejects.toThrow();

        expect(atteint).toBe(false);
    });

    it('laisse passer une réponse directe, pour que le refus veuille dire quelque chose', async () => {
        expect(await outboundJson<{ ok: boolean }>(url('/direct'), { timeoutMs: 5_000 })).toEqual({ ok: true });
    });

    it('lève sur un statut d’erreur plutôt que de rendre une réponse vide', async () => {
        // Sans cela, un webhook refusé en 500 se lirait comme livré, et l'outbox ne le
        // reprendrait jamais.
        const refusant = createServer((_request, response) => {
            response.writeHead(503);
            response.end();
        });
        const port = await listen(refusant);

        await expect(outboundFetch(`http://127.0.0.1:${port}/`, { timeoutMs: 5_000 })).rejects.toThrow(/503/);
        refusant.close();
    });
});
