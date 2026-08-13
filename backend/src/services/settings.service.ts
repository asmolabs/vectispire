import { Injectable } from '@nestjs/common';
import { InjectEntityManager } from '@nestjs/typeorm';
import { EntityManager } from 'typeorm';
import { Setting } from '../persistence/entities';

/**
 * Les réglages, en clé/valeur texte.
 *
 * **Chaque lecteur porte sa clé et sa valeur par défaut**, plutôt qu'un schéma central.
 * C'est ce qui permet d'ajouter un réglage sans migration, et cela impose la contrepartie :
 * une clé absente n'est pas une erreur, c'est le défaut. Un service qui l'oublierait
 * lirait `undefined` là où il attend « true » ou « false », et se comporterait comme si le
 * réglage était désactivé — silencieusement.
 */
@Injectable()
export class SettingsService {
    constructor(@InjectEntityManager() private readonly manager: EntityManager) {}

    async all(): Promise<Record<string, string>> {
        const rows = await this.manager.find(Setting);
        return Object.fromEntries(rows.map((row) => [row.key, row.value ?? '']));
    }

    async get(key: string, fallback = ''): Promise<string> {
        const row = await this.manager.findOneBy(Setting, { key });
        // `?? fallback` et non `|| fallback` : une valeur vide délibérément posée doit
        // rester vide, alors que `||` la remplacerait par le défaut.
        return row?.value ?? fallback;
    }

    /** Un booléen de réglage. Tout ce qui n'est pas « true » est faux — y compris l'absence. */
    async isEnabled(key: string, fallback: boolean): Promise<boolean> {
        return (await this.get(key, fallback ? 'true' : 'false')) === 'true';
    }

    async set(key: string, value: string): Promise<void> {
        // `upsert` et non « lire puis écrire » : deux requêtes concurrentes sur la même clé
        // se marcheraient dessus, et la contrainte de clé primaire ferait échouer la
        // seconde insertion plutôt que de la fusionner.
        await this.manager.upsert(Setting, { key, value }, ['key']);
    }
}
