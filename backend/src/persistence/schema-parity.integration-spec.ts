import { DataSource } from 'typeorm';
import { connectToTestDatabase } from '../../test/database';

/**
 * Les entités et les migrations décrivent-elles le même schéma ?
 *
 * **Elles ont divergé, et rien ne l'a dit.** La migration du ciblage a ajouté une colonne à
 * l'index de la file sans la déclarer sur l'entité ; celle du journal d'audit a créé un
 * index qu'aucune entité ne mentionnait. Conséquences, toutes silencieuses : une génération
 * de migration aurait voulu défaire les deux, et un dialecte dont le schéma est engendré
 * depuis les entités — c'est ainsi que SQLite a reçu le sien — aurait hérité des index
 * d'avant sans qu'aucun test ne s'en aperçoive, puisqu'un index manquant ne change aucun
 * résultat, seulement leur coût.
 *
 * Ce test pose la question que `migration:generate` pose : « que faudrait-il changer pour
 * que la base ressemble aux entités ? ». La bonne réponse est « rien ».
 *
 * Il tourne sur le moteur de la campagne en cours, donc les trois sont couverts tour à
 * tour — et c'est le seul endroit du dépôt qui vérifie cet accord.
 */
describe('accord entre entités et migrations', () => {
    let dataSource: DataSource;

    beforeAll(async () => {
        dataSource = await connectToTestDatabase();
    }, 60_000);

    it("n'a rien à changer après les migrations", async () => {
        const sql = await dataSource.driver.createSchemaBuilder().log();

        // Les deux sens comptent : `upQueries` dit ce qui manque à la base, `downQueries`
        // ce qu'elle porte en trop. Un schéma d'accord n'a ni l'un ni l'autre.
        const differences = [...sql.upQueries, ...sql.downQueries].map((query) => query.query);

        expect(differences).toEqual([]);
    }, 120_000);
});
