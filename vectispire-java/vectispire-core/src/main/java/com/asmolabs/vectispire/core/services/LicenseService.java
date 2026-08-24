package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.licenses.LicenseBlocklist;
import com.asmolabs.vectispire.common.domain.sbom.Sbom;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.persistence.FindingEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Clock;
import java.util.List;
import org.springframework.stereotype.Service;

/**
 * The components whose licence is on the forbidden list.
 *
 * <p>A pure rule evaluated against the SBOM already produced: no network call, no container, no
 * extra tool.
 */
@Service
public class LicenseService implements ScanIngestor.LicenseSource {

    private final SettingsService settings;
    private final Clock clock;

    public LicenseService(SettingsService settings, Clock clock) {
        this.settings = settings;
        this.clock = clock;
    }

    public LicenseBlocklist blocklist() {
        return LicenseBlocklist.parse(settings.get(Setting.LICENSE_BLOCKLIST));
    }

    /** Empty until a list is configured — which licences are forbidden is an organizational call. */
    public boolean isEnabled() {
        return !blocklist().isEmpty();
    }

    @Override
    public List<FindingEntity> findings(ScanEntity scan, JsonNode sbomDocument) {
        return blocklist().violations(new Sbom(sbomDocument)).stream()
                .map(violation -> {
                    FindingEntity finding = new FindingEntity();
                    finding.setScanId(scan.getId());
                    finding.setType(FindingType.LICENSE.wireName());
                    // `medium`, not `high`: a forbidden licence is a legal risk somebody has to
                    // decide on, not an exploitable vulnerability. Grading it higher would fail
                    // builds over a decision that is not technical.
                    finding.setSeverity(Severity.MEDIUM.wireName());
                    finding.setIdentifier(violation.license());
                    finding.setPackageName(violation.packageName());
                    finding.setPackageVersion(violation.packageVersion());
                    finding.setPurl(violation.purl());
                    finding.setSource("syft");
                    finding.setCreatedAt(clock.instant());
                    finding.setIsKev(false);
                    return finding;
                })
                .toList();
    }
}
