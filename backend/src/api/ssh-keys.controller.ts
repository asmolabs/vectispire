import { BadRequestException, Body, Controller, Delete, Get, HttpCode, NotFoundException, Param, Post, Req } from '@nestjs/common';
import { InjectEntityManager } from '@nestjs/typeorm';
import { randomUUID } from 'node:crypto';
import { EntityManager } from 'typeorm';
import { privateKeyContext } from '../domain/crypto/encryption';
import { nowForDatabase } from '../domain/common/timestamp';
import { Repository as GitRepository, SshKey } from '../persistence/entities';
import { AuditLogService } from '../services/audit-log.service';
import { EncryptionService, MissingEncryptionKeyError } from '../services/encryption.service';
import { AdminOnly } from './auth.guard';
import type { AuthenticatedRequest } from './auth.guard';

/** Une clé privée n'a qu'un entête à montrer. Le reste ne sort jamais de la base : il n'y
 *  a aucun écran où l'afficher serait utile, et beaucoup où ce serait une fuite. */
const PRIVATE_KEY_HEADER = /^(-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----)/;

@Controller('api/v1/ssh-keys')
export class SshKeysController {
    constructor(
        @InjectEntityManager() private readonly manager: EntityManager,
        private readonly encryption: EncryptionService = new EncryptionService(),
        private readonly audit: AuditLogService = new AuditLogService()
    ) {}

    /**
     * La liste — **sans jamais la moitié privée**, mais avec son état de chiffrement.
     *
     * Cet état mérite une colonne et non une ligne de journal : une clé lisible seulement
     * sous une clé de chiffrement précédente n'a pas fini d'être tournée, et une clé que
     * *aucune* clé configurée ne lit fera échouer le prochain clone qui en a besoin — au
     * moment du scan, dans un fil d'exécution, des heures plus tard.
     */
    @AdminOnly()
    @Get()
    async list() {
        const [keys, usage] = await Promise.all([
            this.manager.find(SshKey, { order: { createdAt: 'DESC' } }),
            this.usageByKey()
        ]);

        return keys.map((key) => ({
            id: key.id,
            name: key.name,
            publicKey: key.publicKey,
            createdAt: key.createdAt,
            encryptionState: this.encryption.inspect(key.privateKey, privateKeyContext(key.id)).state,
            usedByRepositories: usage.get(key.id) ?? 0
        }));
    }

    @AdminOnly()
    @Post()
    async create(@Body() body: Record<string, unknown>, @Req() request: AuthenticatedRequest) {
        const name = String(body.name ?? '').trim();
        const privateKey = String(body.private_key ?? '').trim();
        const publicKey = String(body.public_key ?? '').trim();

        if (!name) throw new BadRequestException('Le nom est requis.');
        if (!privateKey) throw new BadRequestException('La clé privée est requise.');
        if (!PRIVATE_KEY_HEADER.test(privateKey)) {
            // Refusé à la saisie : sinon l'erreur n'apparaît qu'au premier clone, dans un
            // journal d'agent, et ressemble à un problème de réseau.
            throw new BadRequestException("Ceci ne ressemble pas à une clé privée : attendu un bloc « -----BEGIN … PRIVATE KEY----- ».");
        }

        const id = randomUUID();
        try {
            await this.manager.save(
                SshKey,
                Object.assign(new SshKey(), {
                    id,
                    name,
                    // Le contexte lie le chiffré à *cette* ligne : recopié ailleurs, il
                    // devient illisible plutôt que de déchiffrer la mauvaise clé.
                    privateKey: this.encryption.encrypt(privateKey, privateKeyContext(id)),
                    publicKey: publicKey || null,
                    createdAt: nowForDatabase()
                })
            );
        } catch (error) {
            if (error instanceof MissingEncryptionKeyError) throw new BadRequestException(error.message);
            throw error;
        }

        await this.audit.record(this.manager, {
            operationType: 'SETTING_UPDATED',
            resourceId: id,
            description: `Clé SSH ajoutée : ${name}`,
            userId: request.user?.username ?? null,
            ipAddress: request.ip ?? null
        });
        return { id, name, publicKey: publicKey || null };
    }

    @AdminOnly()
    @Delete(':id')
    @HttpCode(204)
    async remove(@Param('id') id: string, @Req() request: AuthenticatedRequest): Promise<void> {
        const key = await this.manager.findOneBy(SshKey, { id });
        if (!key) throw new NotFoundException('Clé introuvable.');

        const inUse = await this.manager.countBy(GitRepository, { sshKeyId: id });
        if (inUse > 0) {
            // Supprimer la clé casserait le prochain scan de ces dépôts, et l'échec
            // arriverait loin d'ici. Le refus dit combien de dépôts détacher d'abord.
            throw new BadRequestException(`Cette clé est utilisée par ${inUse} dépôt(s). Détachez-la d'abord.`);
        }

        await this.manager.delete(SshKey, { id });
        await this.audit.record(this.manager, {
            operationType: 'SETTING_UPDATED',
            resourceId: id,
            description: `Clé SSH supprimée : ${key.name}`,
            userId: request.user?.username ?? null,
            ipAddress: request.ip ?? null
        });
    }

    private async usageByKey(): Promise<Map<string, number>> {
        const rows: { sshKeyId: string; count: string }[] = await this.manager
            .createQueryBuilder(GitRepository, 'repository')
            .select('repository.ssh_key_id', 'sshKeyId')
            .addSelect('COUNT(*)', 'count')
            .where('repository.ssh_key_id IS NOT NULL')
            .groupBy('repository.ssh_key_id')
            .getRawMany();
        return new Map(rows.map((row) => [row.sshKeyId, Number(row.count)]));
    }
}
