import { Injectable, Logger } from '@nestjs/common';
import { decryptWithAny, deriveKey, encryptWith, type SecretState } from '../domain/crypto/encryption';

export const ENCRYPTION_KEY_ENV_VAR = 'ENCRYPTION_KEY';
export const PREVIOUS_KEYS_ENV_VAR = 'ZANSHIN_PREVIOUS_ENCRYPTION_KEYS';

/** Levée au chiffrement, pas au démarrage : un déploiement existant doit continuer à
 *  *lire* ce qu'il a stocké, et les écrans à s'afficher, tout en refusant d'écrire un
 *  secret qu'il ne saurait pas protéger. */
export class MissingEncryptionKeyError extends Error {
    constructor() {
        super(
            `${ENCRYPTION_KEY_ENV_VAR} n'est pas définie : impossible de chiffrer une nouvelle valeur. ` +
                "Définissez une clé de 32 octets dans l'environnement de Zanshin avant d'enregistrer une clé SSH."
        );
    }
}

/**
 * Le chiffrement au repos, tel que l'environnement le configure.
 *
 * **L'application n'embarque aucune clé vers ses propres secrets.** Une version
 * antérieure en publiait une dans ce dépôt : quiconque tenait une copie de la base
 * lisait toutes les clés SSH privées. Les valeurs anciennes ne sont pas perdues pour
 * autant — un opérateur les rend lisibles en fournissant délibérément l'ancienne clé
 * par `ZANSHIN_PREVIOUS_ENCRYPTION_KEYS`. La différence n'est pas cryptographique,
 * elle est sur qui décide.
 */
@Injectable()
export class EncryptionService {
    private readonly logger = new Logger(EncryptionService.name);
    private readonly encryptionKey: Buffer | null;
    private readonly decryptionKeys: Buffer[];

    constructor(key?: string | null, previousKeys?: readonly string[]) {
        const configured = key !== undefined ? key : process.env[ENCRYPTION_KEY_ENV_VAR];
        this.encryptionKey = configured ? deriveKey(configured) : null;
        if (this.encryptionKey === null) {
            this.logger.warn(`${ENCRYPTION_KEY_ENV_VAR} n'est pas définie — les secrets stockés restent lisibles, mais aucun nouveau ne peut être chiffré.`);
        }

        const previous = previousKeys ?? (process.env[PREVIOUS_KEYS_ENV_VAR] ?? '').split(',').map((part) => part.trim()).filter(Boolean);
        // La courante d'abord, pour qu'une valeur déjà tournée ne se déclare jamais
        // ancienne. Les doublons sont écartés plutôt qu'essayés deux fois.
        this.decryptionKeys = this.encryptionKey ? [this.encryptionKey] : [];
        for (const secret of previous) {
            const derived = deriveKey(secret);
            if (!this.decryptionKeys.some((existing) => existing.equals(derived))) this.decryptionKeys.push(derived);
        }
    }

    /** Permet de signaler la mauvaise configuration *avant* de demander un secret. */
    isConfigured(): boolean {
        return this.encryptionKey !== null;
    }

    encrypt(plainText: string, context?: string | null): string {
        if (!plainText) return plainText;
        if (this.encryptionKey === null) throw new MissingEncryptionKeyError();
        return encryptWith(this.encryptionKey, plainText, context);
    }

    /** L'état est rendu plutôt que journalisé : un secret lisible seulement sous une clé
     *  précédente n'a pas fini d'être tourné, et c'est une information d'écran. */
    inspect(encrypted: string, context?: string | null): { plainText: string; state: SecretState } {
        return decryptWithAny(this.decryptionKeys, encrypted, context);
    }
}
