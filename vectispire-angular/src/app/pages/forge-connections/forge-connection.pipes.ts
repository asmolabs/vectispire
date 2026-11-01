import { Pipe, PipeTransform } from '@angular/core';
import { CA_PROBLEM_KEYS, caCertificateCount, caPemProblem, isCloudAddress } from '../../shared/forge-words';

/** What a pasted CA looks like: the key of its problem, the count of certificates it holds, or neither yet. */
export interface CaFeedback {
    problem: (typeof CA_PROBLEM_KEYS)[keyof typeof CA_PROBLEM_KEYS] | null;
    count: number;
}

export function caFeedback(pem: string): CaFeedback {
    const problem = caPemProblem(pem);
    return {
        problem: problem ? CA_PROBLEM_KEYS[problem] : null,
        count: problem || !pem.trim() ? 0 : caCertificateCount(pem)
    };
}

/**
 * A pasted CA read as {@link caFeedback}. Pure, and answering a key rather than a sentence: the template
 * translates it, so a language switch rewords it without this being called again — and the forms it reads
 * are plain fields the textarea writes, which a `computed` would not see change.
 */
@Pipe({ name: 'caFeedback' })
export class CaFeedbackPipe implements PipeTransform {
    transform(pem: string): CaFeedback {
        return caFeedback(pem);
    }
}

/** Whether an address is a vendor's cloud, which can be neither internal nor pin a CA. Pure, like the above. */
@Pipe({ name: 'cloudAddress' })
export class CloudAddressPipe implements PipeTransform {
    transform(baseUrl: string): boolean {
        return isCloudAddress(baseUrl);
    }
}
