import type { IntelApi } from '../api/intel.api';
import type { AnswerOf } from './contract';

/**
 * The advisor's state as `GET /api/v1/ai-advisor/status` sends it. The document types the route as a
 * bare map; the server builds it with `Map.of`, which refuses a null, so the three fields are always
 * there and `selectedModel` is always a name — the configured one or the default. Specs answered
 * `{ enabled: false }` alone, or `selectedModel: null`, neither of which a server can send.
 */
export function aiAdvisorStatus(
    enabled: boolean,
    changes: Partial<AnswerOf<IntelApi['getAiAdvisorStatus']>> = {}
): AnswerOf<IntelApi['getAiAdvisorStatus']> {
    return { enabled, selectedModel: 'llama3', availableModels: enabled ? ['llama3'] : [], ...changes };
}
