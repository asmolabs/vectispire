import { BadRequestException, Body, Controller, Get, Put, Req } from '@nestjs/common';
import { InjectEntityManager } from '@nestjs/typeorm';
import { ApiTags } from '@nestjs/swagger';
import { EntityManager } from 'typeorm';
import { SETTINGS_CATALOG, definitionFor, validate } from '../domain/settings/catalog';
import { ADMIN_ROLES } from '../domain/users/roles';
import { AuditLogService } from '../services/audit-log.service';
import { SettingsService } from '../services/settings.service';
import { TicketService } from '../services/ticket.service';
import { AdminOnly } from './auth.guard';
import type { AuthenticatedRequest } from './auth.guard';

/**
 * Les réglages, lus par tous et écrits par les administrateurs.
 *
 * **Le catalogue décide de tout.** Une clé qui n'y figure pas est refusée à l'écriture, ce
 * qui donne deux propriétés d'un coup : l'écran n'a pas à connaître la liste, et la table
 * `t_setting` ne peut pas se remplir de clés qu'aucun service ne lit — l'état exact qui
 * fait croire à un opérateur qu'il a configuré quelque chose.
 *
 * **Chaque écriture est auditée**, comme toute action d'administration : passer le seuil de
 * notification de `high` à `critical` change ce que l'organisation voit, et c'est le genre
 * de décision qu'on veut pouvoir dater.
 */
@ApiTags('Administration')
@Controller('api/v1/settings')
export class SettingsController {
    constructor(
        @InjectEntityManager() private readonly manager: EntityManager,
        private readonly settings: SettingsService,
        private readonly audit: AuditLogService,
        private readonly tickets: TicketService
    ) {}

    /**
     * Le catalogue et les valeurs courantes.
     *
     * Les deux ensemble plutôt que les seules valeurs : l'écran a besoin du type pour
     * choisir son contrôle, et de l'explication pour dire ce que le réglage ne fait pas.
     */
    @Get()
    async list(@Req() request: AuthenticatedRequest) {
        const values = await this.settings.all();
        // **La valeur d'un réglage sensible ne sort que pour un administrateur.**
        // Une URL de webhook est une capacité au porteur : qui la lit peut publier dans le
        // canal où l'équipe attend les alertes de Zanshin. Le catalogue, lui, reste
        // lisible par tous — l'écran a besoin des libellés et des types.
        const isAdmin = ADMIN_ROLES.includes(request.user?.role as (typeof ADMIN_ROLES)[number]);

        return {
            settings: SETTINGS_CATALOG.map((definition) => ({
                key: definition.key,
                type: definition.type,
                section: definition.section,
                label: definition.label,
                help: definition.help,
                default: definition.default,
                // La valeur effective, défaut compris : sans cela l'écran afficherait un
                // champ vide là où le service applique pourtant une valeur.
                value: definition.sensitive && !isAdmin ? null : (values[definition.key] ?? definition.default),
                // Distingué explicitement, parce que « jamais réglé » et « réglé à la même
                // valeur que le défaut » ne se disent pas pareil à un opérateur.
                configured: definition.key in values
            }))
        };
    }

    @AdminOnly()
    @Put()
    async update(@Body() body: Record<string, unknown>, @Req() request: AuthenticatedRequest) {
        const entries = Object.entries(body ?? {});
        if (entries.length === 0) throw new BadRequestException('Aucun réglage fourni.');

        const changes: { key: string; value: string }[] = [];
        for (const [key, raw] of entries) {
            const definition = definitionFor(key);
            if (!definition) throw new BadRequestException(`Réglage inconnu : « ${key} ».`);

            const value = typeof raw === 'string' ? raw.trim() : String(raw ?? '');
            const problem = validate(definition, value);
            if (problem) throw new BadRequestException(`${definition.label} — ${problem}`);
            changes.push({ key, value });
        }

        // Toutes validées avant qu'aucune ne soit écrite : une écriture partielle laisserait
        // la configuration à mi-chemin entre deux états voulus.
        for (const change of changes) await this.settings.set(change.key, change.value);

        await this.audit.record(this.manager, {
            operationType: 'SETTINGS_UPDATED',
            resourceId: changes.map((change) => change.key).join(','),
            // Les valeurs sont journalisées : aucun réglage du catalogue n'est un secret,
            // et savoir *ce que* quelqu'un a changé est tout l'intérêt de l'entrée.
            description: changes.map((change) => `${change.key} = ${change.value || '(vide)'}`).join(' ; '),
            userId: request.user?.username ?? null,
            ipAddress: request.ip ?? null
        });

        return { updated: changes.length };
    }

    /**
     * Le jeton du gestionnaire de tickets, écrit seulement.
     *
     * **Sa propre route, hors du catalogue**, parce qu'un secret ne se comporte pas comme
     * un réglage : il est chiffré au repos, il ne peut pas être relu dans un formulaire, et
     * l'écran ne peut donc afficher que « configuré » ou « absent ». Le faire passer par la
     * route générique aurait demandé une exception à chaque étape — lecture, validation,
     * audit — et l'une d'elles aurait fini par être oubliée.
     */
    @AdminOnly()
    @Put('ticket-token')
    async setTicketToken(@Body() body: Record<string, unknown>, @Req() request: AuthenticatedRequest) {
        const token = typeof body.token === 'string' ? body.token : '';
        await this.tickets.setToken(token);

        await this.audit.record(this.manager, {
            operationType: 'SETTINGS_UPDATED',
            resourceId: 'ticket_token',
            // La valeur n'est **pas** journalisée, contrairement aux autres réglages : la
            // piste d'audit est lisible par tout administrateur.
            description: token ? 'Jeton du gestionnaire de tickets enregistré.' : 'Jeton du gestionnaire de tickets effacé.',
            userId: request.user?.username ?? null,
            ipAddress: request.ip ?? null
        });

        return { configured: token !== '' };
    }

    /** L'état du jeton, sans jamais le rendre. */
    @Get('ticket-token')
    async ticketTokenState() {
        return { configured: (await this.tickets.token()) !== '' };
    }
}
