import { Injectable } from '@nestjs/common';
import { EntityManager } from 'typeorm';
import { PREFIX_LENGTH } from '../domain/api-keys/api-key-rules';
import { now } from '../domain/common/timestamp';
import { Agent, ApiKey } from '../persistence/entities';
import { verifyPassword } from './password.service';

/**
 * L'authentification par clé d'API.
 *
 * **Le préfixe est ce qui rend ceci praticable.** Sans lui, vérifier une clé demanderait un
 * bcrypt par clé existante à chaque requête — soit un déni de service offert à qui présente
 * n'importe quoi. Le préfixe de douze caractères, stocké en clair parce qu'il n'est pas un
 * secret, réduit les candidats à un ou deux.
 *
 * **Une clé expirée est refusée mais sa ligne est conservée.** La piste d'audit a besoin de
 * savoir qu'elle a existé, et un opérateur qui voit « expirée » comprend mieux qu'un
 * opérateur qui ne voit rien.
 */
@Injectable()
export class ApiKeyAuthService {
    /** Rend la clé si elle est valable, `null` sinon. Ne dit jamais *pourquoi* : la
     *  distinction entre « inconnue » et « expirée » renseignerait un attaquant. */
    async resolve(manager: EntityManager, presented: string): Promise<ApiKey | null> {
        const trimmed = presented.trim();
        if (trimmed.length <= PREFIX_LENGTH) return null;

        const candidates = await manager.findBy(ApiKey, { prefix: trimmed.slice(0, PREFIX_LENGTH) });
        const asOf = now();

        for (const candidate of candidates) {
            if (!verifyPassword(trimmed, candidate.keyHash)) continue;
            if (candidate.expiresAt !== null && candidate.expiresAt <= asOf) return null;

            // `lastUsedAt` est posé sans attendre : c'est la seule trace qui permette à un
            // opérateur de repérer une clé émise pour un usage qui n'a jamais eu lieu.
            await manager.update(ApiKey, { id: candidate.id }, { lastUsedAt: asOf });
            return candidate;
        }
        return null;
    }

    /** La clé porte-t-elle ce périmètre ? */
    hasScope(key: ApiKey, scope: string): boolean {
        return (key.scopes ?? '').split(',').map((value) => value.trim()).includes(scope);
    }

    /** L'agent associé à cette clé, s'il en existe un d'activé. */
    async agentFor(manager: EntityManager, key: ApiKey): Promise<Agent | null> {
        return manager.findOneBy(Agent, { apiKeyId: key.id });
    }
}
