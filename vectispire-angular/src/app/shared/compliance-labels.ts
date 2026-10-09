import { Pipe, PipeTransform, inject } from '@angular/core';
import { I18nService } from '../core/i18n/i18n.service';
import { keyFor } from '../core/i18n/literal-keys';
import type { ComplianceFramework, ComplianceStatus, TargetCompliance } from '../core/api.models';

/**
 * A verdict in words. Literal keys, so that the i18n check sees every one of them (decision 0019):
 * the tags used to show the wire value, and `NO_DATA` reached the reader as a constant — the
 * attestation's framework tiles still did, "PARTIAL" and "NON_COMPLIANT" under a French title.
 */
export const COMPLIANCE_STATUS_KEYS = {
    COMPLIANT: 'soa.measured.COMPLIANT',
    PARTIAL: 'soa.measured.PARTIAL',
    NON_COMPLIANT: 'soa.measured.NON_COMPLIANT',
    NO_DATA: 'soa.measured.NO_DATA'
} as const satisfies Record<ComplianceStatus, string>;

/**
 * A framework's name, not its Java constant. The compliance progress printed `ISO_27001` as a
 * heading, the attestation rewrote the constant with `replace('_', ' ')`, and the summary kept a
 * third list of its own — three spellings of six names. `satisfies` makes a framework the document
 * adds a build failure here rather than a constant on a screen.
 */
export const FRAMEWORK_KEYS = {
    NIS_2: 'compliance.frameworks.nis2',
    ISO_27001: 'compliance.frameworks.iso27001',
    EU_CRA: 'compliance.frameworks.eu_cra',
    DORA: 'compliance.frameworks.dora',
    PCI_DSS: 'compliance.frameworks.pci_dss',
    SOC_2: 'compliance.frameworks.soc2'
} as const satisfies Record<ComplianceFramework, string>;

export const FRAMEWORK_DESCRIPTION_KEYS = {
    NIS_2: 'compliance.frameworks.nis2_desc',
    ISO_27001: 'compliance.frameworks.iso27001_desc',
    EU_CRA: 'compliance.frameworks.eu_cra_desc',
    DORA: 'compliance.frameworks.dora_desc',
    PCI_DSS: 'compliance.frameworks.pci_dss_desc',
    SOC_2: 'compliance.frameworks.soc2_desc'
} as const satisfies Record<ComplianceFramework, string>;

/**
 * A target's gate in the compliance matrix. `PASSED` and `FAILED` are the matrix's own words; the
 * other four say what another screen already says, so they read the same here as there.
 */
export const GATE_STATUS_KEYS = {
    PASSED: 'compliance.gate_passed',
    FAILED: 'compliance.gate_failed',
    NEVER_SCANNED: 'scans.never_scanned',
    LAST_SCAN_FAILED: 'dashboard.last_scan_failed',
    SCANNING: 'scans.status_running',
    IN_PROGRESS: 'scans.status_running'
} as const satisfies Record<TargetCompliance['gateStatus'], string>;

/** The order every screen lists them in. */
export const FRAMEWORKS: readonly ComplianceFramework[] = ['NIS_2', 'ISO_27001', 'EU_CRA', 'DORA', 'PCI_DSS', 'SOC_2'];

/**
 * Open sets, all four: the server can be newer than this client, and a declaration's framework is a
 * plain string (`OWASP_2021` is one). What the client does not know is shown as sent.
 */
export function complianceStatusLabel(i18n: Pick<I18nService, 't'>, status: string | null | undefined): string {
    if (status == null || status === '') return '—';
    const key = keyFor(COMPLIANCE_STATUS_KEYS, status);
    return key ? i18n.t(key) : status;
}

export function gateStatusLabel(i18n: Pick<I18nService, 't'>, status: string): string {
    const key = keyFor(GATE_STATUS_KEYS, status);
    return key ? i18n.t(key) : status;
}

export function frameworkLabel(i18n: Pick<I18nService, 't'>, framework: string): string {
    const key = keyFor(FRAMEWORK_KEYS, framework);
    return key ? i18n.t(key) : framework;
}

export function frameworkDescription(i18n: Pick<I18nService, 't'>, framework: string): string {
    const key = keyFor(FRAMEWORK_DESCRIPTION_KEYS, framework);
    return key ? i18n.t(key) : framework;
}

@Pipe({
    name: 'complianceStatus',
    // Impure like `translate`: the text changes when the language does.
    pure: false
})
export class ComplianceStatusPipe implements PipeTransform {
    private readonly i18n = inject(I18nService);

    transform(status: string | null | undefined): string {
        return complianceStatusLabel(this.i18n, status);
    }
}

@Pipe({
    name: 'frameworkLabel',
    pure: false
})
export class FrameworkLabelPipe implements PipeTransform {
    private readonly i18n = inject(I18nService);

    transform(framework: string): string {
        return frameworkLabel(this.i18n, framework);
    }
}
