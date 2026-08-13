import { UnsafeUrlError, unsafeReason, validateOutboundUrl } from './url-guard';

/** Une résolution DNS simulée : les tests ne doivent pas dépendre du réseau. */
function resolving(map: Record<string, string[]>) {
    return async (hostname: string) => map[hostname] ?? [];
}

const PUBLIC = resolving({ 'exemple.test': ['93.184.216.34'] });

describe('validateOutboundUrl', () => {
    it('accepte une destination publique pour un webhook', async () => {
        await expect(validateOutboundUrl('https://exemple.test/hook', { allowPrivate: false, resolve: PUBLIC })).resolves.toBe(
            'https://exemple.test/hook'
        );
    });

    it('refuse le point de métadonnées, même quand le privé est autorisé', async () => {
        // La cible classique : elle remet les identifiants de l'instance à qui les
        // demande. Rien de légitime ne vit dans cette plage.
        await expect(
            validateOutboundUrl('http://169.254.169.254/latest/meta-data/', { allowPrivate: true })
        ).rejects.toThrow(/link-local/);
    });

    it('refuse un nom qui résout vers le link-local', async () => {
        // Le contournement évident : cacher l'adresse derrière un nom.
        await expect(
            validateOutboundUrl('http://metadata.interne/', { allowPrivate: true, resolve: resolving({ 'metadata.interne': ['169.254.169.254'] }) })
        ).rejects.toThrow(/link-local/);
    });

    it("refuse une adresse privée quand une destination publique est attendue", async () => {
        for (const address of ['10.0.0.5', '172.16.3.1', '192.168.1.10', '127.0.0.1', '100.64.0.1']) {
            await expect(
                validateOutboundUrl(`http://hote.interne/`, { allowPrivate: false, resolve: resolving({ 'hote.interne': [address] }) })
            ).rejects.toThrow(/privée ou locale/);
        }
    });

    it('refuse un nom dont une seule des adresses est privée', async () => {
        // Toutes les adresses sont vérifiées, pas la première : n'en vérifier qu'une
        // laisserait passer l'autre.
        await expect(
            validateOutboundUrl('https://double.test/', {
                allowPrivate: false,
                resolve: resolving({ 'double.test': ['93.184.216.34', '10.0.0.5'] })
            })
        ).rejects.toThrow(/privée ou locale/);
    });

    it('accepte le privé pour une annexe locale', async () => {
        await expect(validateOutboundUrl('http://127.0.0.1:8000/scan', { allowPrivate: true })).resolves.toContain('127.0.0.1');
    });

    it('refuse une destination publique quand une destination interne est exigée', async () => {
        // Ollama reçoit le code source : le risque n'est pas l'interne, c'est l'externe.
        // Une URL publique bien formée est exactement ce à quoi ressemble une exfiltration.
        await expect(
            validateOutboundUrl('https://exemple.test/api', { allowPrivate: true, requirePrivate: true, resolve: PUBLIC })
        ).rejects.toThrow(/reçoit du code source/);
    });

    it("refuse un nom irrésoluble quand une destination interne est exigée", async () => {
        // Échouer ouvert est défendable pour « est-ce privé ? », pas pour « ceci doit
        // l'être » : un nom irrésoluble ne prouve rien.
        await expect(
            validateOutboundUrl('https://inconnu.test/', { allowPrivate: true, requirePrivate: true, resolve: resolving({}) })
        ).rejects.toThrow(/n'a pas pu être résolu/);
    });

    it('refuse les schémas hors http et https', async () => {
        for (const url of ['file:///etc/passwd', 'gopher://exemple.test/', 'ftp://exemple.test/']) {
            await expect(validateOutboundUrl(url, { allowPrivate: true })).rejects.toThrow(/schéma/);
        }
    });

    it('refuse une valeur vide ou illisible', async () => {
        await expect(validateOutboundUrl('', { allowPrivate: true })).rejects.toThrow(UnsafeUrlError);
        await expect(validateOutboundUrl('pas une url', { allowPrivate: true })).rejects.toThrow(UnsafeUrlError);
    });

    it('accepte un nom irrésoluble pour un webhook', async () => {
        // Un hoquet DNS ne doit pas rendre l'écran des réglages inutilisable, et la
        // requête elle-même échouerait de toute façon.
        await expect(
            validateOutboundUrl('https://inconnu.test/hook', { allowPrivate: false, resolve: resolving({}) })
        ).resolves.toBe('https://inconnu.test/hook');
    });
});

describe('unsafeReason', () => {
    it('rend la raison au lieu de lever', async () => {
        expect(await unsafeReason('https://exemple.test/', { allowPrivate: false, resolve: PUBLIC })).toBeNull();
        expect(await unsafeReason('http://10.0.0.1/', { allowPrivate: false })).toMatch(/privée ou locale/);
    });
});
