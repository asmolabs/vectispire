import { createServer, type Server } from 'node:http';
import { outboundFetch, outboundJson } from './outbound';

/**
 * Le refus des redirections, contre de vrais serveurs.
 *
 * **This behaviour cannot be simulated.** It is decided by Node's HTTP client, not by any
 * code in this repository: a fake `fetch` would only prove the fake does what it was
 * dit. Deux serveurs suffisent — l'un redirige, l'autre joue la destination interne que le
 * URL guard would have refused.
 *
 * What these tests protect: `validateOutboundUrl` only checks the **first** request. Node
 * follows redirects by default, so a validated destination answering
 * `302 Location: http://169.254.169.254/` was followed with nothing re-checking. The
 * costliest case is the model review, whose guard demands an internal destination precisely
 * because it receives the scanned repository's source code.
 */
describe('appel sortant', () => {
    let interne: Server;
    let redirecteur: Server;
    let atteint = false;

    /** Starts a server on a free port and returns that port. */
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
        // what matters is that the internal destination received nothing.
        expect(atteint).toBe(false);
    });

    it('refuse aussi sur un GET JSON', async () => {
        await expect(outboundJson(url('/redirige'), { timeoutMs: 5_000 })).rejects.toThrow();

        expect(atteint).toBe(false);
    });

    it('lets a direct response through, so the refusal means something', async () => {
        expect(await outboundJson<{ ok: boolean }>(url('/direct'), { timeoutMs: 5_000 })).toEqual({ ok: true });
    });

    it('throws on an error status rather than returning an empty response', async () => {
        // Without this, a webhook refused with a 500 would read as delivered, and the outbox
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
