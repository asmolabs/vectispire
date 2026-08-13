import { Injectable, Logger } from '@nestjs/common';
import {
    DEFAULT_AI_REVIEW_MODEL,
    DEFAULT_OLLAMA_URL,
    FALLBACK_MODEL_SUGGESTIONS,
    SECURITY_ARCHITECT_PROMPT,
    SETTING_AI_REVIEW_ALLOW_REMOTE,
    SETTING_AI_REVIEW_ENABLED,
    SETTING_AI_REVIEW_MODEL,
    SETTING_AI_REVIEW_OLLAMA_URL,
    buildUserMessage
} from '../domain/ai-review/prompt';
import { validateOutboundUrl } from '../domain/net/url-guard';
import { SettingsService } from './settings.service';

const LIST_TIMEOUT_MS = 5_000;
const REVIEW_TIMEOUT_MS = 120_000;

export type HttpJson = (url: string, body?: unknown, timeoutMs?: number) => Promise<Record<string, unknown>>;

/**
 * La revue de code par un modèle local, via Ollama.
 *
 * **Un complément léger aux scanners, pas un moteur SAST** : une seule invite contre le
 * modèle configuré, sans chaîne d'analyse. Désactivée par défaut.
 *
 * **L'URL d'Ollama doit rester interne, et c'est l'inverse du webhook.** Ce point de
 * terminaison reçoit le **code source** du dépôt scanné : le risque n'est pas qu'il pointe
 * vers l'interne, c'est qu'il pointe vers l'externe. Un administrateur — ou quelqu'un qui
 * en a hameçonné un — qui la dirige vers son propre serveur transforme la revue en canal
 * d'exfiltration, et une URL publique bien formée est parfaitement normale aux yeux d'un
 * garde anti-SSRF. D'où `requirePrivate`, et un réglage d'aveu explicite pour l'ouvrir.
 */
@Injectable()
export class AiReviewService {
    private readonly logger = new Logger(AiReviewService.name);

    constructor(
        private readonly settings: SettingsService,
        private readonly getJson: HttpJson = defaultGetJson,
        private readonly postJson: HttpJson = defaultPostJson
    ) {}

    async isEnabled(): Promise<boolean> {
        return this.settings.isEnabled(SETTING_AI_REVIEW_ENABLED, false);
    }

    async ollamaUrl(): Promise<string> {
        return (await this.settings.get(SETTING_AI_REVIEW_OLLAMA_URL, DEFAULT_OLLAMA_URL)) || DEFAULT_OLLAMA_URL;
    }

    async allowRemote(): Promise<boolean> {
        return this.settings.isEnabled(SETTING_AI_REVIEW_ALLOW_REMOTE, false);
    }

    async selectedModel(): Promise<string> {
        return (await this.settings.get(SETTING_AI_REVIEW_MODEL, DEFAULT_AI_REVIEW_MODEL)) || DEFAULT_AI_REVIEW_MODEL;
    }

    /**
     * L'URL validée, refusant une destination publique par défaut.
     *
     * **Revalidée à chaque appel**, et pas seulement à l'enregistrement : c'est ici que le
     * code source quitte réellement le processus, et le réglage peut avoir été écrit
     * directement en base ou dater d'avant le garde.
     */
    async validatedUrl(): Promise<string> {
        return validateOutboundUrl(await this.ollamaUrl(), {
            allowPrivate: true,
            requirePrivate: !(await this.allowRemote()),
            label: 'URL Ollama'
        });
    }

    /** Enregistre l'URL après validation — le point de saisie est là où l'erreur coûte peu. */
    async setOllamaUrl(url: string): Promise<void> {
        if (!url?.trim()) throw new Error("L'URL du service Ollama ne peut pas être vide.");

        await validateOutboundUrl(url, {
            allowPrivate: true,
            requirePrivate: !(await this.allowRemote()),
            label: 'URL Ollama'
        });
        await this.settings.set(SETTING_AI_REVIEW_OLLAMA_URL, url.trim());
    }

    /**
     * Les modèles réellement installés sur l'hôte configuré.
     *
     * **Ne lève jamais** : si Ollama est injoignable, une courte liste de suggestions est
     * rendue à la place — jamais présentée comme installée, seulement comme quelque chose
     * de raisonnable à saisir pendant l'installation.
     */
    async availableModels(): Promise<string[]> {
        try {
            const url = `${(await this.validatedUrl()).replace(/\/+$/, '')}/api/tags`;
            const payload = await this.getJson(url, undefined, LIST_TIMEOUT_MS);
            const models = Array.isArray(payload.models)
                ? (payload.models as Record<string, unknown>[]).map((model) => String(model.name ?? '')).filter(Boolean)
                : [];
            return models.length > 0 ? models : [...FALLBACK_MODEL_SUGGESTIONS];
        } catch (error) {
            this.logger.warn(`Ollama injoignable pour lister les modèles (${(error as Error).message}) — suggestions rendues.`);
            return [...FALLBACK_MODEL_SUGGESTIONS];
        }
    }

    /**
     * Envoie le code au modèle et rend sa réponse brute.
     *
     * **Lève en cas d'échec**, contrairement aux méthodes de configuration ci-dessus : un
     * appelant qui veut une revue doit savoir qu'il n'en a pas eu. C'est à lui de
     * l'enregistrer sur la ligne de résultat plutôt que de faire échouer le scan.
     */
    async reviewCode(code: string, prompt: string = SECURITY_ARCHITECT_PROMPT): Promise<string> {
        const url = `${(await this.validatedUrl()).replace(/\/+$/, '')}/api/chat`;
        const payload = await this.postJson(
            url,
            {
                model: await this.selectedModel(),
                messages: [
                    { role: 'system', content: prompt },
                    { role: 'user', content: buildUserMessage(code) }
                ],
                stream: false
            },
            REVIEW_TIMEOUT_MS
        );
        return String((payload.message as { content?: unknown } | undefined)?.content ?? '');
    }
}

async function defaultGetJson(url: string, _body?: unknown, timeoutMs = LIST_TIMEOUT_MS): Promise<Record<string, unknown>> {
    const response = await fetch(url, { signal: AbortSignal.timeout(timeoutMs) });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return (await response.json()) as Record<string, unknown>;
}

async function defaultPostJson(url: string, body?: unknown, timeoutMs = REVIEW_TIMEOUT_MS): Promise<Record<string, unknown>> {
    const response = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(timeoutMs)
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return (await response.json()) as Record<string, unknown>;
}
