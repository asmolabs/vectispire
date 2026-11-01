import { Pipe, PipeTransform } from '@angular/core';
import { severityTone, type SeverityTone } from '@/app/shared/severity';

/**
 * What the attack graph draws from a node's or a path's own values, as pure pipes: each depends on
 * its value alone, so Angular calls it again only for a new one — the methods they replace ran for
 * every node of the graph on every pass.
 */

/** `node.severity | severityTone` — the shared scale (`SEVERITY_TONES`), the same as every screen's. */
@Pipe({ name: 'severityTone' })
export class SeverityTonePipe implements PipeTransform {
    transform(severity: string | null | undefined): SeverityTone {
        return severityTone(severity);
    }
}

/** `node.type | nodeIcon` — a node's icon and colour by what it is in the chain. */
@Pipe({ name: 'nodeIcon' })
export class NodeIconPipe implements PipeTransform {
    transform(type: string): string {
        switch (type) {
            case 'INTERNET_INGRESS':
                return 'pi pi-globe text-blue-500';
            case 'API_ENDPOINT':
                return 'pi pi-link text-amber-500';
            case 'VULNERABLE_COMPONENT':
                return 'pi pi-shield text-rose-500';
            case 'SECRET':
                return 'pi pi-key text-yellow-500';
            case 'DATABASE':
                return 'pi pi-database text-purple-500';
            default:
                return 'pi pi-box text-surface-400';
        }
    }
}

/** `g.riskScore | riskScoreColor` — a risk score's colour: red from 75, amber from 40, green below. */
@Pipe({ name: 'riskScoreColor' })
export class RiskScoreColorPipe implements PipeTransform {
    transform(score: number): string {
        if (score >= 75) return 'text-rose-600 dark:text-rose-400';
        if (score >= 40) return 'text-amber-500';
        return 'text-emerald-600 dark:text-emerald-400';
    }
}
