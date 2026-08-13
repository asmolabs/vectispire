import { Injectable, Logger } from '@nestjs/common';
import { validateOutboundUrl } from '../domain/net/url-guard';
import {
    DEFAULT_JIRA_ISSUE_TYPE,
    DEFAULT_LABELS,
    PROVIDER_GITLAB,
    PROVIDER_NONE,
    type TicketableIssue,
    buildBody,
    buildTitle,
    parseLabels,
    parseProvider
} from '../domain/tickets/ticket';
import {
    SETTING_TICKET_ALLOW_PRIVATE_URL,
    SETTING_TICKET_BASE_URL,
    SETTING_TICKET_ISSUE_TYPE,
    SETTING_TICKET_LABELS,
    SETTING_TICKET_PROJECT,
    SETTING_TICKET_PROVIDER,
    SETTING_TICKET_TOKEN,
    SETTING_TICKET_USER
} from '../domain/settings/keys';
import { EncryptionService } from './encryption.service';
import { SettingsService } from './settings.service';

/** Le contexte de chiffrement du jeton, lié à sa clé de réglage. */
export const TOKEN_CONTEXT = 'setting:ticket_token';

const HTTP_TIMEOUT_MS = 15_000;

export interface Ticket {
    reference: string;
    url: string;
}

/** Ce qu'il faut pour appeler un gestionnaire de tickets. Injectable pour les tests. */
export type PostTicket = (url: string, body: unknown, headers: Record<string, string>) => Promise<Record<string, unknown>>;

/**
 * L'ouverture d'un ticket chez GitLab ou Jira.
 *
 * **Le jeton est chiffré au repos.** Il donne un accès en écriture au gestionnaire, ce qui
 * est une autre classe de secret qu'une URL de webhook : il passe donc par le service de
 * chiffrement comme une clé SSH, au lieu de dormir en clair dans la table des réglages.
 *
 * **Un ticket par problème, pour toute sa vie.** Pas par scan, et jamais rouvert quand le
 * problème réapparaît : un ticket qui revient d'entre les morts à chaque rescan est la
 * façon dont les gens apprennent à couper les notifications d'un projet. `ticketRef` est
 * posé une fois et jamais effacé — c'est aussi la clé de déduplication du balayage.
 */
@Injectable()
export class TicketService {
    private readonly logger = new Logger(TicketService.name);

    constructor(
        private readonly settings: SettingsService,
        private readonly encryption: EncryptionService | null = null,
        private readonly postTicket: PostTicket = defaultPostTicket
    ) {}

    async provider(): Promise<string> {
        return parseProvider(await this.settings.get(SETTING_TICKET_PROVIDER, PROVIDER_NONE));
    }

    async baseUrl(): Promise<string> {
        return (await this.settings.get(SETTING_TICKET_BASE_URL, '')).trim().replace(/\/+$/, '');
    }

    async project(): Promise<string> {
        return (await this.settings.get(SETTING_TICKET_PROJECT, '')).trim();
    }

    async isEnabled(): Promise<boolean> {
        const [provider, baseUrl, project, token] = await Promise.all([
            this.provider(),
            this.baseUrl(),
            this.project(),
            this.token()
        ]);
        return provider !== PROVIDER_NONE && Boolean(baseUrl) && Boolean(project) && Boolean(token);
    }

    /**
     * Le jeton déchiffré, ou une chaîne vide.
     *
     * **Ne lève jamais** : un jeton indéchiffrable — une clé de chiffrement tournée, par
     * exemple — doit désactiver l'ouverture de tickets, pas casser le tour d'entretien qui
     * appelle ceci et qui porte aussi la purge et l'expiration des triages.
     */
    async token(): Promise<string> {
        const stored = (await this.settings.get(SETTING_TICKET_TOKEN, '')).trim();
        if (!stored || !this.encryption) return stored;

        const secret = this.encryption.inspect(stored, TOKEN_CONTEXT);
        if (secret.state === 'unreadable') {
            this.logger.error("Le jeton du gestionnaire de tickets n'est déchiffrable par aucune clé — ouverture de tickets désactivée.");
            return '';
        }
        return secret.plainText;
    }

    /** Enregistre le jeton chiffré, lié à sa propre clé de réglage. */
    async setToken(rawToken: string): Promise<void> {
        const value = (rawToken ?? '').trim();
        if (!value) {
            await this.settings.set(SETTING_TICKET_TOKEN, '');
            return;
        }
        if (!this.encryption) throw new Error('Le service de chiffrement est requis pour enregistrer un jeton.');
        await this.settings.set(SETTING_TICKET_TOKEN, this.encryption.encrypt(value, TOKEN_CONTEXT));
    }

    /**
     * Ouvre un ticket. Rend `null` sur toute panne, après l'avoir journalisée.
     *
     * Ne lève jamais : ceci tourne depuis le tour d'entretien, et un gestionnaire
     * injoignable ne doit pas arrêter les autres travaux qui le partagent.
     */
    async createForIssue(issue: TicketableIssue, targetName: string): Promise<Ticket | null> {
        if (!(await this.isEnabled())) return null;

        let baseUrl: string;
        try {
            // **Validée ici aussi**, et pas seulement à l'enregistrement : un réglage
            // écrit directement en base ne doit pas devenir une destination non vérifiée.
            baseUrl = await this.validatedBaseUrl(await this.baseUrl());
        } catch (error) {
            this.logger.error(`Ticket non créé : ${(error as Error).message}`);
            return null;
        }

        try {
            const title = buildTitle(issue, targetName);
            const body = buildBody(issue, targetName);
            return (await this.provider()) === PROVIDER_GITLAB
                ? await this.createGitlab(baseUrl, title, body)
                : await this.createJira(baseUrl, title, body);
        } catch (error) {
            this.logger.warn(`Création de ticket échouée pour le problème ${issue.id} — sera retentée : ${(error as Error).message}`);
            return null;
        }
    }

    /**
     * L'URL de base, validée.
     *
     * **Le privé est autorisé par défaut ici**, contrairement au webhook de notification :
     * un GitLab ou un Jira auto-hébergé vit couramment sur un réseau interne. Le réglage
     * reste là pour l'interdire à un déploiement qui n'utilise qu'un gestionnaire hébergé.
     */
    async validatedBaseUrl(url: string): Promise<string> {
        const validated = await validateOutboundUrl(url, {
            allowPrivate: await this.settings.isEnabled(SETTING_TICKET_ALLOW_PRIVATE_URL, true),
            label: 'URL du gestionnaire de tickets'
        });
        return validated.replace(/\/+$/, '');
    }

    private async labels(): Promise<string[]> {
        return parseLabels(await this.settings.get(SETTING_TICKET_LABELS, DEFAULT_LABELS));
    }

    private async createGitlab(baseUrl: string, title: string, body: string): Promise<Ticket> {
        // L'identifiant de projet doit être encodé quand c'est un chemin
        // (« groupe/projet »), qui est la forme sous laquelle la plupart des gens l'ont.
        const url = `${baseUrl}/api/v4/projects/${encodeURIComponent(await this.project())}/issues`;
        const payload = await this.postTicket(
            url,
            { title, description: body, labels: (await this.labels()).join(',') },
            { 'PRIVATE-TOKEN': await this.token() }
        );
        return { reference: `#${payload.iid}`, url: String(payload.web_url ?? '') };
    }

    private async createJira(baseUrl: string, title: string, body: string): Promise<Ticket> {
        const labels = await this.labels();
        const fields: Record<string, unknown> = {
            project: { key: await this.project() },
            summary: title,
            issuetype: { name: (await this.settings.get(SETTING_TICKET_ISSUE_TYPE, DEFAULT_JIRA_ISSUE_TYPE)) || DEFAULT_JIRA_ISSUE_TYPE },
            // Format de document Atlassian : l'API v3 de Jira Cloud refuse une chaîne
            // simple pour `description`.
            description: {
                type: 'doc',
                version: 1,
                content: body
                    .split('\n')
                    .filter((line) => line.trim() !== '')
                    .map((line) => ({ type: 'paragraph', content: [{ type: 'text', text: line }] }))
            }
        };
        if (labels.length > 0) fields.labels = labels;

        const user = (await this.settings.get(SETTING_TICKET_USER, '')).trim();
        const headers: Record<string, string> = { Accept: 'application/json' };
        // Jira exige l'adresse du compte à côté du jeton pour l'authentification de base ;
        // GitLab ne s'en sert pas.
        if (user) headers.Authorization = `Basic ${Buffer.from(`${user}:${await this.token()}`).toString('base64')}`;

        const payload = await this.postTicket(`${baseUrl}/rest/api/3/issue`, { fields }, headers);
        const key = String(payload.key ?? '');
        return { reference: key, url: key ? `${baseUrl}/browse/${key}` : '' };
    }
}

async function defaultPostTicket(url: string, body: unknown, headers: Record<string, string>): Promise<Record<string, unknown>> {
    const response = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...headers },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(HTTP_TIMEOUT_MS)
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return (await response.json()) as Record<string, unknown>;
}
