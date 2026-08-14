import { ScanRunner } from './scan-runner';

/**
 * Le scan d'une image de conteneur, contre de vraies images.
 *
 * **Ce chemin n'existait pas.** `generateSbomForImage` était écrit et n'était appelé par
 * personne ; le distributeur refusait explicitement tout scan sans dépôt. L'écran
 * Conteneurs permettait d'enregistrer une image et de demander un scan — qui échouait à
 * chaque fois. Trouvé en cherchant à distribuer ce scan aux agents, pas par un test.
 *
 * Ce qui se vérifie ici ne se simule pas : Syft lit réellement l'image depuis le registre,
 * et Grype apparie réellement le SBOM produit.
 */
describe("scan d'une image de conteneur", () => {
    const runner = new ScanRunner();

    it("dresse l'inventaire d'une image et l'apparie", async () => {
        // `alpine` : petite, stable, et elle porte de vrais paquets système — donc un SBOM
        // non vide sans faire tirer plusieurs centaines de mégaoctets à chaque campagne.
        const artifacts = await runner.run({ image: 'alpine:3.20', url: '', branch: 'n/a' });

        expect(artifacts.failures).toEqual([]);
        expect(artifacts.sbom).not.toBeNull();
        expect((artifacts.sbom as { artifacts?: unknown[] }).artifacts?.length).toBeGreaterThan(0);
        // Une liste, éventuellement vide : `alpine` à jour peut n'avoir aucun CVE connu, et
        // `[]` dit « analysé, rien trouvé » là où `null` dirait « pas analysé ».
        expect(Array.isArray(artifacts.dependencies)).toBe(true);
        expect(artifacts.durationMs).toBeGreaterThan(0);
    }, 300_000);

    it("laisse à `null` les étapes qui ne s'appliquent pas à une image", async () => {
        // **Le point qui décide du sort du backlog.** Secrets, IaC et SAST cherchent dans du
        // code source ; une image n'en fournit pas. Les déclarer scannés — donc `[]` —
        // résoudrait en silence tout leur historique pour cette cible.
        const artifacts = await runner.run({ image: 'alpine:3.20', url: '', branch: 'n/a' });

        expect(artifacts.secrets).toBeNull();
        expect(artifacts.iac).toBeNull();
        expect(artifacts.sast).toBeNull();
    }, 300_000);

    it("rend un échec nommé sur une image qui n'existe pas, sans lever", async () => {
        // Un scan qui échoue doit le dire dans `failures` : sans cela, l'opérateur verrait
        // un scan terminé avec zéro constat et le lirait comme une bonne nouvelle.
        const artifacts = await runner.run({ image: 'zanshin-image-inexistante:0.0.0', url: '', branch: 'n/a' });

        expect(artifacts.sbom).toBeNull();
        expect(artifacts.dependencies).toBeNull();
        expect(artifacts.failures.length).toBeGreaterThan(0);
    }, 300_000);
});
