import {
    BadRequestException,
    Body,
    ConflictException,
    Controller,
    Get,
    Headers,
    HttpCode,
    NotFoundException,
    Param,
    ParseIntPipe,
    Post,
    PreconditionFailedException,
    Query,
    Req,
    Res,
    UnauthorizedException
} from '@nestjs/common';
import type { Response } from 'express';
import { InjectEntityManager } from '@nestjs/typeorm';
import { ApiTags } from '@nestjs/swagger';
import { RuleSetService } from '../services/rule-set.service';
import { DataSource, EntityManager } from 'typeorm';
import { now } from '../domain/common/timestamp';
import { CONTRACT_VERSION, isCompatibleContract } from '../domain/agents/contract';
import { Agent, CREDENTIALS_DELEGATED } from '../persistence/entities';
import { InsecureCredentialTransport, ScanDispatcherService } from '../services/scan-dispatcher.service';
import { isUsablePublicKey } from '../domain/crypto/sealed-envelope';
import { Public } from './auth.guard';
import type { AuthenticatedRequest } from './auth.guard';

/**
 * Le protocole des agents distants.
 *
 * Quatre routes, et une seule idée : un agent est un travailleur **sans accès à la base**.
 * Il annonce sa présence, réclame une tâche, donne signe de vie pendant qu'il travaille, et
 * rend son résultat. Tout ce qu'il sait du plan de contrôle passe par ces quatre appels.
 *
 * **`Public` ne veut pas dire ouvert.** Ces routes sont hors du garde de session parce
 * qu'un agent n'a pas de session : il s'authentifie par une clé d'API portant le périmètre
 * `agent`. La vérification est faite ici, explicitement.
 */
@Public()
@ApiTags('Agents')
@Controller('api/v1/agents')
export class AgentsController {
    constructor(
        @InjectEntityManager() private readonly manager: EntityManager,
        private readonly dataSource: DataSource,
        private readonly dispatcher: ScanDispatcherService,
        private readonly ruleSets: RuleSetService
    ) {}

    /**
     * L'annonce d'un agent, et **le premier diagnostic d'un opérateur**.
     *
     * Si cet appel répond, l'URL, la clé, le périmètre et la ligne d'agent sont tous
     * corrects — c'est-à-dire l'essentiel de ce qui peut être mal configuré.
     */
    @Post('hello')
    async hello(@Body() body: Record<string, unknown>, @Req() request: AuthenticatedRequest) {
        const agent = await this.authenticate(request);
        const announced = String(body.contract_version ?? '');

        if (!isCompatibleContract(announced)) {
            // 409 et non 400 : la requête est bien formée, les deux côtés sont simplement
            // en désaccord sur le protocole — et le correctif est un déploiement, pas un
            // autre appel.
            throw new ConflictException(
                `Cet agent parle le contrat « ${announced || 'inconnu' } » et Zanshin le contrat « ${CONTRACT_VERSION} ». Mettez l'agent à jour.`
            );
        }

        // **Refusée si elle n'est pas exploitable, plutôt que stockée telle quelle.** Une
        // valeur illisible provoquerait une exception au milieu d'une réclamation ; `null`
        // fait simplement retomber cet agent sur le comportement d'avant — clé en clair sur
        // liaison chiffrée — ce qui est un mode dégradé, pas une panne.
        const sealingKey = asText(body.sealing_public_key);
        if (sealingKey !== null && !isUsablePublicKey(sealingKey)) {
            throw new BadRequestException("La clé de scellement annoncée n'est pas une clé publique X25519 lisible.");
        }

        await this.manager.update(Agent, { id: agent.id }, {
            sealingPublicKey: sealingKey,
            hostname: asText(body.hostname),
            platform: asText(body.platform),
            version: asText(body.version),
            scannerEngine: asText(body.scanner_engine),
            capabilities: (body.capabilities ?? null) as never,
            contractVersion: announced,
            lastSeenAt: now()
        });

        return {
            id: agent.id,
            name: agent.name,
            contractVersion: CONTRACT_VERSION,
            maxConcurrent: agent.maxConcurrent ?? 1,
            credentialsMode: agent.credentialsMode
        };
    }

    /**
     * Le contenu d'un jeu de règles, par son empreinte.
     *
     * **Récupéré par empreinte et non « le jeu actif »**, et c'est la moitié du propos : un
     * agent qui demanderait le jeu actif recevrait ce qui l'est *à cet instant*, alors que
     * sa tâche a été construite plus tôt. Deux agents pourraient scanner la même cible avec
     * des règles différentes, ce qui est précisément la divergence que le téléversement
     * supprime. L'empreinte vient de la tâche, donc un scan est reproductible même si un
     * administrateur active autre chose pendant qu'il tourne.
     *
     * Immuable par construction : une empreinte désigne un contenu, jamais un état. Un agent
     * peut donc la mettre en cache sans invalidation.
     */
    @Get('rules/:hash')
    async ruleSet(@Param('hash') hash: string) {
        const found = await this.ruleSets.byHash(hash);
        // 404 plutôt qu'un jeu vide : l'agent doit échouer son étape SAST, pas scanner avec
        // les seules règles embarquées et rendre une liste plus courte qui se lirait
        // « analysé, ces problèmes ont disparu ».
        if (!found) throw new NotFoundException(`No rule set with hash ${hash}.`);

        return { contentHash: found.contentHash, files: found.files };
    }

    /**
     * Réclame une tâche, ou rend 204.
     *
     * **204 et non un objet vide** : la question « y a-t-il du travail ? » doit se lire au
     * code de statut, sans analyser un corps.
     */
    @Get('jobs')
    async claimJob(
        @Req() request: AuthenticatedRequest,
        @Res({ passthrough: true }) response: Response,
        @Headers('x-forwarded-proto') forwardedProto?: string,
        @Query('wait') wait?: string
    ) {
        const agent = await this.authenticate(request);
        const secure = isSecureTransport(request, forwardedProto);

        // **Le refus n'est pas décidé ici.** Il l'était, en doublon de la même règle dans le
        // distributeur — et les deux copies divergeaient déjà : celle-ci refusait un agent
        // `delegated` sur une liaison en clair même quand le dépôt n'a aucune clé, et elle
        // ignorait le scellement. Seul le distributeur sait ce que la tâche contient
        // réellement ; il lève `InsecureCredentialTransport`, traduite plus bas en 412.

        let task: Awaited<ReturnType<ScanDispatcherService['claimForAgent']>>;
        try {
            task = await this.dispatcher.claimForAgent(agent, secure, boundedWait(wait));
        } catch (error) {
            // **Traduite ici, et non laissée remonter.** Sa classe existe précisément pour
            // devenir un 412 plutôt qu'un 500 : un agent qui reçoit « erreur interne » ne
            // peut rien en faire, alors que « votre liaison n'est pas chiffrée » nomme le
            // correctif. Le commentaire de cette classe l'annonçait ; personne ne
            // l'attrapait.
            if (error instanceof InsecureCredentialTransport) throw new PreconditionFailedException(error.message);
            throw error;
        }

        if (task === null) {
            response.status(204);
            return undefined;
        }
        return task;
    }

    /**
     * Le signe de vie d'un agent qui travaille encore.
     *
     * C'est ce qui distingue « long » de « mort » : sans lui, un scan de vingt minutes
     * verrait son bail expirer et serait repris par un autre, qui referait le même travail
     * pendant que le premier le termine.
     */
    @Post('jobs/:scanId/heartbeat')
    @HttpCode(204)
    async heartbeat(@Param('scanId', ParseIntPipe) scanId: number, @Req() request: AuthenticatedRequest): Promise<void> {
        const agent = await this.authenticate(request);
        const renewed = await this.dispatcher.renewAgentLease(scanId, agent);
        if (!renewed) {
            // 409 : le bail a été repris pendant que l'agent travaillait. Il doit
            // abandonner plutôt que de rendre un résultat qui écraserait celui du
            // successeur.
            throw new ConflictException('Ce scan ne vous appartient plus : son bail a été repris.');
        }
    }

    /** Le résultat d'un scan exécuté ailleurs. */
    @Post('jobs/:scanId/result')
    async submitResult(
        @Param('scanId', ParseIntPipe) scanId: number,
        @Body() body: Record<string, unknown>,
        @Req() request: AuthenticatedRequest
    ) {
        const agent = await this.authenticate(request);
        const accepted = await this.dispatcher.acceptAgentResult(scanId, agent, body);
        if (!accepted) {
            throw new ConflictException('Ce scan ne vous appartient plus : ses résultats ont été écartés.');
        }
        return { accepted: true };
    }

    /**
     * Authentifie par clé d'API portant le périmètre `agent`, et rend l'agent associé.
     *
     * Le garde de session ne s'applique pas ici, donc cette vérification est la seule :
     * l'oublier sur une route ouvrirait la file de scans à qui connaît l'URL.
     */
    private async authenticate(request: AuthenticatedRequest): Promise<Agent> {
        const agent = request.agent;
        if (!agent) throw new UnauthorizedException("Clé d'API absente, invalide, ou sans le périmètre « agent ».");
        if (!agent.enabled) throw new UnauthorizedException(`L'agent « ${agent.name} » est désactivé.`);
        return agent;
    }
}

/**
 * Cette requête est-elle arrivée par une liaison chiffrée ?
 *
 * `X-Forwarded-Proto` est honoré parce que le déploiement prévu place un proxy inverse
 * devant, où l'application ne voit jamais que du HTTP. **Cet en-tête est trivialement
 * falsifiable** par qui peut atteindre ce port directement — c'est pourquoi il ne décide
 * que d'une chose : si une clé de déploiement peut voyager. Une décision que l'opérateur a
 * déjà dû prendre agent par agent.
 */
function isSecureTransport(request: AuthenticatedRequest, forwardedProto?: string): boolean {
    if ((forwardedProto ?? '').split(',')[0].trim().toLowerCase() === 'https') return true;
    return request.protocol === 'https';
}

/** Bornée : une attente non plafonnée retiendrait une connexion indéfiniment. */
function boundedWait(wait?: string): number {
    const seconds = Number(wait ?? 0);
    return Number.isFinite(seconds) ? Math.min(Math.max(0, seconds), 30) : 0;
}

function asText(value: unknown): string | null {
    const text = typeof value === 'string' ? value.trim() : '';
    return text || null;
}
