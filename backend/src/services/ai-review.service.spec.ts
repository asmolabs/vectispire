import { FALLBACK_MODEL_SUGGESTIONS } from '../domain/ai-review/prompt';
import { AiReviewService } from './ai-review.service';
import type { SettingsService } from './settings.service';

function settings(values: Record<string, string> = {}): SettingsService {
    const store = { ...values };
    return {
        get: async (key: string, fallback = '') => store[key] ?? fallback,
        set: async (key: string, value: string) => {
            store[key] = value;
        },
        isEnabled: async (key: string, fallback: boolean) => (store[key] ?? (fallback ? 'true' : 'false')) === 'true',
        all: async () => ({ ...store })
    } as unknown as SettingsService;
}

function ollama(response: Record<string, unknown>) {
    const calls: { url: string; body?: unknown }[] = [];
    const http = async (url: string, body?: unknown) => {
        calls.push({ url, body });
        if (response instanceof Error) throw response;
        return response;
    };
    return { calls, http };
}

describe('AiReviewService', () => {
    it('refuse une URL publique : ce point de terminaison reçoit du code source', async () => {
        // L'inverse du webhook. Le risque n'est pas que l'URL pointe vers l'interne, c'est
        // qu'elle pointe vers l'externe — et une URL publique bien formée est parfaitement
        // normale aux yeux d'un garde anti-SSRF.
        const { calls, http } = ollama({});
        const service = new AiReviewService(settings({ ai_review_ollama_url: 'https://ollama-public.example.com' }), http, http);

        await expect(service.reviewCode('print(1)')).rejects.toThrow(/code source/);
        expect(calls).toEqual([]);
    });

    it('accepte une URL publique quand l\'opérateur l\'a explicitement autorisée', async () => {
        const { http } = ollama({ message: { content: '[]' } });
        const service = new AiReviewService(
            settings({ ai_review_ollama_url: 'https://ollama-public.example.com', ai_review_allow_remote_url: 'true' }),
            http,
            http
        );

        await expect(service.reviewCode('print(1)')).resolves.toBe('[]');
    });

    it('appelle Ollama en local par défaut', async () => {
        const { calls, http } = ollama({ message: { content: '[{"title":"X"}]' } });
        const service = new AiReviewService(settings(), http, http);

        expect(await service.reviewCode('print(1)')).toBe('[{"title":"X"}]');
        expect(calls[0].url).toBe('http://localhost:11434/api/chat');

        const body = calls[0].body as { model: string; messages: { role: string; content: string }[]; stream: boolean };
        expect(body.model).toBe('gemma4:12b-it-qat');
        expect(body.stream).toBe(false);
        expect(body.messages[1].content).toContain('print(1)');
    });

    it('lève quand Ollama refuse : un appelant doit savoir qu\'il n\'a pas eu de revue', async () => {
        const http = async () => {
            throw new Error('HTTP 500');
        };
        const service = new AiReviewService(settings(), http, http);

        await expect(service.reviewCode('print(1)')).rejects.toThrow('HTTP 500');
    });

    it('liste les modèles réellement installés', async () => {
        const { calls, http } = ollama({ models: [{ name: 'gemma4:12b-it-qat' }, { name: 'llama3:8b' }] });
        const service = new AiReviewService(settings(), http, http);

        expect(await service.availableModels()).toEqual(['gemma4:12b-it-qat', 'llama3:8b']);
        expect(calls[0].url).toBe('http://localhost:11434/api/tags');
    });

    it('retombe sur des suggestions quand Ollama est injoignable, sans lever', async () => {
        // Pour que l'écran des réglages ne soit pas vide pendant l'installation — jamais
        // présentées comme installées.
        const http = async () => {
            throw new Error('ECONNREFUSED');
        };
        const service = new AiReviewService(settings(), http, http);

        expect(await service.availableModels()).toEqual(FALLBACK_MODEL_SUGGESTIONS);
    });

    it('valide au point de saisie et refuse une valeur vide', async () => {
        const { http } = ollama({});
        const service = new AiReviewService(settings(), http, http);

        await expect(service.setOllamaUrl('')).rejects.toThrow(/vide/);
        await expect(service.setOllamaUrl('https://ollama-public.example.com')).rejects.toThrow(/code source/);
        await expect(service.setOllamaUrl('http://127.0.0.1:11434')).resolves.toBeUndefined();
    });

    it('est désactivée par défaut', async () => {
        expect(await new AiReviewService(settings()).isEnabled()).toBe(false);
    });
});
