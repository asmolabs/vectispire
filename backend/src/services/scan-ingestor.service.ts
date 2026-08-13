import { Injectable } from '@nestjs/common';
import { EntityManager } from 'typeorm';
import { now } from '../domain/common/timestamp';
import { buildFingerprint } from '../domain/issues/issue-fingerprint';
import { TYPE_EOL, TYPE_IAC, TYPE_QUALITY, TYPE_SAST, TYPE_SECRET, TYPE_VULNERABILITY } from '../domain/issues/types';
import { Finding, Scan } from '../persistence/entities';
import type { ScanArtifacts } from '../scanning/scan-runner';
import { EnrichmentService } from './enrichment.service';
import { EolService } from './eol.service';
import { IssueSyncService } from './issue-sync.service';

/**
 * La traduction des artefacts d'un scan en constats, puis en problèmes.
 *
 * **`scannedTypes` est le pivot, et la subtilité la plus coûteuse à rater.** Un type y
 * figure si et seulement si l'étape correspondante a **réellement tourné** : « le scanner
 * de secrets a tourné et n'a rien trouvé » doit résoudre les problèmes de type secret,
 * tandis que « aucun constat parce qu'on n'a pas cherché » doit les laisser intacts. La
 * distinction est portée par `null` contre `[]` dans les artefacts, et c'est ici qu'elle
 * se transforme en décision.
 *
 * Se tromper ici résout en silence tout l'historique d'un type — sans erreur, sans
 * journal, et sans que personne ne s'en aperçoive avant l'audit suivant.
 */
@Injectable()
export class ScanIngestorService {
    constructor(
        private readonly sync: IssueSyncService = new IssueSyncService(),
        /**
         * Facultatif, et c'est délibéré : l'enrichissement appelle le réseau. Les tests
         * d'ingestion qui ne l'injectent pas restent hors ligne et déterministes, au lieu
         * de dépendre de la disponibilité de FIRST et de la CISA.
         */
        private readonly enrichment: EnrichmentService | null = null,
        /** Même raison : la détection de fin de vie consulte un catalogue distant. */
        private readonly eol: EolService | null = null
    ) {}

    async ingest(manager: EntityManager, scan: Scan, artifacts: ScanArtifacts) {
        const findings: Finding[] = [];
        const scannedTypes: string[] = [];
        const descriptions: Record<string, string> = {};

        if (artifacts.dependencies !== null) {
            scannedTypes.push(TYPE_VULNERABILITY);
            for (const dependency of artifacts.dependencies) {
                if (dependency.description) descriptions[dependency.identifier] = dependency.description;
                findings.push(
                    this.finding(scan, {
                        type: TYPE_VULNERABILITY,
                        source: 'grype',
                        identifier: dependency.identifier,
                        severity: dependency.severity,
                        packageName: dependency.packageName,
                        packageVersion: dependency.installedVersion,
                        fixVersions: dependency.fixVersions,
                        link: dependency.referenceUrl,
                        purl: dependency.purl
                    })
                );
            }
        }

        if (artifacts.secrets !== null) {
            scannedTypes.push(TYPE_SECRET);
            for (const secret of artifacts.secrets) {
                findings.push(
                    this.finding(scan, {
                        type: TYPE_SECRET,
                        source: 'gitleaks',
                        identifier: secret.rule,
                        // Un secret codé en dur est toujours grave : il n'y a pas de
                        // sévérité à graduer, seulement une clé à révoquer.
                        severity: 'high',
                        filePath: secret.file,
                        line: secret.line,
                        description: secret.description
                    })
                );
            }
        }

        if (artifacts.iac !== null) {
            scannedTypes.push(TYPE_IAC);
            for (const check of artifacts.iac) {
                findings.push(
                    this.finding(scan, {
                        type: TYPE_IAC,
                        source: 'checkov',
                        identifier: check.checkId,
                        severity: 'medium',
                        filePath: check.file,
                        line: check.line,
                        description: check.checkName,
                        link: check.guideline
                    })
                );
            }
        }

        if (artifacts.sast !== null) {
            // **Les deux types entrent ensemble.** Un seul passage de Semgrep cherche la
            // sécurité et la qualité ; n'en déclarer qu'un résoudrait en silence tout
            // l'historique de l'autre.
            scannedTypes.push(TYPE_SAST, TYPE_QUALITY);
            for (const result of artifacts.sast) {
                findings.push(
                    this.finding(scan, {
                        // C'est la catégorie de la règle qui décide de la destination —
                        // `security` au backlog de sécurité, le reste à la qualité, qui ne
                        // fait jamais échouer une compilation.
                        type: result.category === 'security' ? TYPE_SAST : TYPE_QUALITY,
                        source: 'semgrep',
                        identifier: result.ruleId,
                        severity: this.downgradeLowConfidence(result.severity, result.confidence),
                        filePath: result.file,
                        line: result.line,
                        description: result.message
                    })
                );
            }
        }

        // La fin de vie se lit du SBOM. **Le type n'est déclaré scanné que si la détection
        // était activée et qu'un SBOM existait** : sans l'une ou l'autre, rien n'a été
        // observé, et le déclarer résoudrait en silence tout l'historique de ce type —
        // « on a cessé de regarder » n'est pas « c'est réglé ».
        if (this.eol && artifacts.sbom && (await this.eol.isEnabled())) {
            scannedTypes.push(TYPE_EOL);
            const eolFindings = await this.eol.buildFindings(scan, artifacts.sbom as unknown as Record<string, unknown>);
            for (const finding of eolFindings) {
                if (finding.identifier) descriptions[finding.identifier] = this.eol.describe(finding);
            }
            findings.push(...eolFindings);
        }

        // **Avant l'écriture, et non après.** Les constats sont enregistrés par `sync` ;
        // les enrichir ensuite demanderait une seconde écriture, hors de la transaction du
        // scan, et laisserait une fenêtre où le gate verrait des constats sans leur
        // drapeau KEV — c'est-à-dire un verdict vert sur une vulnérabilité exploitée.
        if (this.enrichment) await this.enrichment.enrich(findings);

        return this.sync.sync(manager, scan, findings, { scannedTypes, descriptions });
    }

    /**
     * Une règle peu sûre descend d'un cran, elle n'est pas supprimée.
     *
     * Supprimer ferait disparaître le constat, qui réapparaîtrait à neuf le jour où la
     * métadonnée change — triage perdu. Descendre sous le seuil de gate par défaut donne
     * exactement « visible dans le backlog, incapable de casser une compilation ».
     */
    private downgradeLowConfidence(severity: string, confidence: string | null): string {
        if (confidence !== 'LOW') return severity;
        const lower: Record<string, string> = { critical: 'high', high: 'medium', medium: 'low', low: 'low' };
        return lower[severity] ?? severity;
    }

    private finding(scan: Scan, values: Partial<Finding> & { type: string; identifier: string; severity: string; source: string }): Finding {
        const finding = Object.assign(new Finding(), {
            scanId: scan.id,
            // `createdAt` posé ici : la colonne est obligatoire et un défaut de base
            // s'appliquerait *après* l'insertion, donc trop tard pour l'entité en mémoire.
            createdAt: now(),
            isKev: false,
            ...values,
            // L'empreinte est l'identité d'un problème à travers les scans : c'est elle
            // qui fait qu'un CVE revu la semaine suivante incrémente un compteur au lieu
            // de créer un doublon, et qui préserve le triage posé dessus.
            fingerprint: buildFingerprint({
                repoId: scan.repoId,
                containerId: scan.containerId,
                findingType: values.type,
                identifier: values.identifier,
                purl: values.purl ?? null,
                packageName: values.packageName ?? null,
                filePath: values.filePath ?? null
            })
        });
        return finding;
    }
}
