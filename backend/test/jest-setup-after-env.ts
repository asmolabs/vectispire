import { disconnectFromTestDatabase } from './database';

/**
 * Ferme la connexion du processus à la fin de chaque fichier de test.
 *
 * Sans cela, Jest signale des descripteurs ouverts et attend son expiration avant de
 * rendre la main — un symptôme qu'on prend facilement pour un test lent.
 */
afterAll(async () => {
    await disconnectFromTestDatabase();
});
