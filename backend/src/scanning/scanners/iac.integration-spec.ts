import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { ContainerRunner } from '../container-runner';
import { withWorkspace } from '../workspace';
import { IacScanner } from './iac';
import { CHECKOV_IMAGE } from './images';

/**
 * checkov de bout en bout, sur un manifeste Terraform délibérément fautif.
 *
 * Le seau S3 ci-dessous cumule trois défauts que checkov reconnaît de longue date —
 * chiffrement absent, versionnage absent, journalisation absente. Choisir des contrôles
 * anciens plutôt que récents est délibéré : un contrôle ajouté cette année pourrait être
 * renuméroté ou retiré, et le test deviendrait instable pour une raison étrangère à son
 * sujet.
 */
const TERRAFORM = `
resource "aws_s3_bucket" "donnees" {
  bucket = "zanshin-essai"
}
`;

describe('analyse IaC', () => {
    const runner = new ContainerRunner();
    const scanner = new IacScanner(runner);

    beforeAll(async () => {
        if (!(await runner.isAvailable())) {
            throw new Error('Le démon Docker est injoignable : ce test exerce un vrai conteneur et ne peut pas être simulé.');
        }
        await new Promise<void>((resolve, reject) => {
            void runner['docker'].pull(CHECKOV_IMAGE, (error: Error | null, stream: NodeJS.ReadableStream) => {
                if (error) return reject(error);
                runner['docker'].modem.followProgress(stream, (done: Error | null) => (done ? reject(done) : resolve()));
            });
        });
    }, 600_000);

    it('trouve les contrôles en échec et dit où', async () => {
        await withWorkspace(async (workspace) => {
            await mkdir(workspace.source, { recursive: true });
            await writeFile(join(workspace.source, 'main.tf'), TERRAFORM);

            const findings = await scanner.scan(workspace);

            expect(findings).not.toBeNull();
            expect(findings!.length).toBeGreaterThan(0);
            const first = findings![0];
            expect(first.checkId).toMatch(/^CKV/);
            expect(first.checkName).toBeTruthy();
            // Le chemin est relatif à l'arbre scanné, jamais celui du conteneur : sinon le
            // même fichier porterait deux identités selon l'endroit d'où il a été analysé.
            expect(first.file).toBe('main.tf');
            expect(first.file.startsWith('/repo')).toBe(false);
        });
    }, 600_000);

    it('rend une liste vide sur un arbre sans manifeste', async () => {
        await withWorkspace(async (workspace) => {
            await mkdir(workspace.source, { recursive: true });
            await writeFile(join(workspace.source, 'README.md'), '# rien à analyser\n');

            // Vide et non `null` : checkov a tourné et n'a rien trouvé, ce qui doit
            // résoudre les constats IaC précédents.
            expect(await scanner.scan(workspace)).toEqual([]);
        });
    }, 600_000);

    it('rend null plutôt qu’une liste vide quand il ne peut pas tourner', async () => {
        // Le point de tout ce fichier : `[]` signifie « analysé, propre », ce que
        // l'ingestion lit comme l'autorisation de résoudre chaque problème IaC de la
        // cible. Un plantage déclarerait donc un dépôt corrigé.
        const brokenRunner = {
            run: async () => {
                throw new Error('démon indisponible');
            }
        } as unknown as ContainerRunner;

        await withWorkspace(async (workspace) => {
            expect(await new IacScanner(brokenRunner).scan(workspace)).toBeNull();
        });
    }, 30_000);
});
