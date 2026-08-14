import { Injectable, Logger } from '@nestjs/common';
import { outboundFetch } from '../domain/net/outbound';
import { validateOutboundUrl } from '../domain/net/url-guard';
import {
    DEFAULT_MIN_SEVERITY,
    type DeltaInput,
    type NotifiableIssue,
    SETTING_ALLOW_PRIVATE_URL,
    SETTING_MIN_SEVERITY,
    SETTING_NOTIFY_ON_KEV,
    SETTING_WEBHOOK_URL,
    buildPayload,
    selectNotable
} from '../domain/notifications/payload';
import { SettingsService } from './settings.service';

const HTTP_TIMEOUT_MS = 10_000;

/** Ce qu'il faut pour poster une charge : l'URL validée et le corps. */
export type PostJson = (url: string, body: unknown) => Promise<void>;

/**
 * L'envoi de ce qu'un scan a changé.
 *
 * Ce service possède **quoi dire et comment le dire** ; le relais d'outbox possède **quand
 * un message a droit à une nouvelle chance**. Les garder séparés est ce qui rend la
 * politique de reprise testable sans webhook, et la charge testable sans horloge.
 */
@Injectable()
export class NotificationService {
    private readonly logger = new Logger(NotificationService.name);

    constructor(
        private readonly settings: SettingsService,
        private readonly postJson: PostJson = defaultPostJson
    ) {}

    async webhookUrl(): Promise<string> {
        return (await this.settings.get(SETTING_WEBHOOK_URL, '')).trim();
    }

    /** Activé veut dire « une URL est configurée » : il n'y a pas d'autre interrupteur. */
    async isEnabled(): Promise<boolean> {
        return (await this.webhookUrl()) !== '';
    }

    async minSeverity(): Promise<string> {
        return ((await this.settings.get(SETTING_MIN_SEVERITY, DEFAULT_MIN_SEVERITY)) || DEFAULT_MIN_SEVERITY).toLowerCase();
    }

    /**
     * Construit la charge d'un delta de scan, ou rend `null` quand il n'y a rien à dire.
     *
     * Séparé de l'envoi parce que les deux ont lieu à des moments différents : le message
     * est bâti et mis en file **dans la transaction qui valide les résultats du scan**, et
     * livré plus tard par le relais.
     */
    async buildScanDelta(input: {
        targetName: string;
        scanId: number;
        newIssues: NotifiableIssue[];
        reopenedIssues?: NotifiableIssue[];
        resolvedCount?: number;
    }): Promise<Record<string, unknown> | null> {
        if (!(await this.isEnabled())) return null;

        const options = {
            minSeverity: await this.minSeverity(),
            alwaysOnKev: await this.settings.isEnabled(SETTING_NOTIFY_ON_KEV, true)
        };
        const newIssues = selectNotable(input.newIssues, options);
        const reopenedIssues = selectNotable(input.reopenedIssues ?? [], options);
        if (newIssues.length === 0 && reopenedIssues.length === 0) return null;

        const delta: DeltaInput = {
            targetName: input.targetName,
            scanId: input.scanId,
            newIssues,
            reopenedIssues,
            resolvedCount: input.resolvedCount ?? 0,
            minSeverity: options.minSeverity
        };
        return buildPayload(delta);
    }

    /**
     * Poste une charge. **Lève en cas d'échec**, pour que le relais puisse la reprendre.
     *
     * Contrat inverse de tout le reste de cette classe, et délibérément : une panne avalée
     * est une panne jamais reprise, ce qui est toute la raison d'être de l'outbox. C'est le
     * relais qui retransforme l'exception en « non fatal ».
     *
     * **L'URL est relue et validée ici**, et non capturée à la mise en file : un opérateur
     * qui corrige une faute de frappe ne doit pas avoir à relancer un scan pour faire
     * sortir les notifications en attente, et un réglage écrit directement en base ne doit
     * pas devenir une destination non vérifiée.
     */
    async deliver(payload: Record<string, unknown>): Promise<void> {
        const url = await validateOutboundUrl(await this.webhookUrl(), {
            allowPrivate: await this.settings.isEnabled(SETTING_ALLOW_PRIVATE_URL, false),
            label: 'URL de webhook'
        });

        await this.postJson(url, payload);
        this.logger.log(
            `Webhook notifié pour le scan ${payload.scan_id} (${payload.new_count} nouveau(x), ${payload.reopened_count} réapparu(s)).`
        );
    }
}

// Le corps de la réponse n'est pas lu : le récepteur n'a rien à nous dire, et un proxy peut
// rendre une page d'erreur de plusieurs kilooctets. Les redirections sont refusées — voir
// `outboundFetch` : sans cela, un webhook validé qui répond 302 rejoint n'importe quelle
// adresse interne.
async function defaultPostJson(url: string, body: unknown): Promise<void> {
    await outboundFetch(url, { method: 'POST', body, timeoutMs: HTTP_TIMEOUT_MS });
}
