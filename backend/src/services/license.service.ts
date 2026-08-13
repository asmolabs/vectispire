import { Injectable } from '@nestjs/common';
import { now } from '../domain/common/timestamp';
import { findViolations, parseBlocklist } from '../domain/licenses/blocklist';
import { buildFingerprint } from '../domain/issues/issue-fingerprint';
import { TYPE_LICENSE } from '../domain/issues/types';
import { SETTING_LICENSE_BLOCKLIST } from '../domain/settings/keys';
import { Finding, Scan } from '../persistence/entities';
import { SettingsService } from './settings.service';

/**
 * Les composants dont la licence figure sur la liste interdite.
 *
 * Pure évaluation d'une règle sur le SBOM déjà produit : aucun appel réseau, aucun
 * conteneur, aucun outil supplémentaire.
 */
@Injectable()
export class LicenseService {
    constructor(private readonly settings: SettingsService) {}

    async blocklist(): Promise<Set<string>> {
        return parseBlocklist(await this.settings.get(SETTING_LICENSE_BLOCKLIST, ''));
    }

    /** Vide tant qu'aucune liste n'est configurée — c'est une décision d'organisation. */
    async isEnabled(): Promise<boolean> {
        return (await this.blocklist()).size > 0;
    }

    async buildFindings(scan: Scan, sbom: Record<string, unknown> | null): Promise<Finding[]> {
        if (!sbom) return [];

        const blocklist = await this.blocklist();
        return findViolations(sbom, blocklist).map((violation) =>
            Object.assign(new Finding(), {
                scanId: scan.id,
                type: TYPE_LICENSE,
                // `medium` et non `high` : une licence interdite est un risque juridique à
                // trancher, pas une vulnérabilité exploitable. La graduer plus haut ferait
                // échouer des compilations pour une décision qui n'est pas technique.
                severity: 'medium',
                identifier: violation.license,
                packageName: violation.packageName,
                packageVersion: violation.packageVersion,
                purl: violation.purl,
                source: 'syft',
                createdAt: now(),
                isKev: false,
                fingerprint: buildFingerprint({
                    repoId: scan.repoId,
                    containerId: scan.containerId,
                    findingType: TYPE_LICENSE,
                    identifier: violation.license,
                    purl: violation.purl,
                    packageName: violation.packageName,
                    filePath: null
                })
            })
        );
    }
}
