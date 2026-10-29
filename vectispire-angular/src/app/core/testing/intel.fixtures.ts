import type { IntelApi } from '../api/intel.api';
import type { AiVulnerabilityAdvice } from '../api.models';
import { asSchema, type AnswerOf } from './contract';

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

/** The advisor's answer about CVE-2026-11 as a model writes it, its VEX suggestion saying `status`. */
export function vulnerabilityAdvice(status: string): AiVulnerabilityAdvice {
    return asSchema('AiVulnerabilityAdvice', {
        identifier: 'CVE-2026-11',
        title: '',
        summaryExplanation: 'Remote code execution.',
        exploitMechanics: '',
        exposureAssessment: '',
        remediation: { fixAction: '', suggestedVersion: '', codeSnippetOrDiff: '', cliCommand: '' },
        vexSuggestion: { status, justification: '', impactStatement: 'Reachable.', actionStatement: '' },
        references: []
    });
}
