package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.attestation.InTotoAttestation;
import com.asmolabs.zanshin.common.domain.crypto.Digests;
import com.asmolabs.zanshin.common.domain.issues.Severity;
import com.asmolabs.zanshin.core.persistence.RepositoryEntity;
import com.asmolabs.zanshin.core.persistence.ScanEntity;
import com.asmolabs.zanshin.core.repositories.Findings;
import com.asmolabs.zanshin.core.repositories.GitRepositories;
import com.asmolabs.zanshin.core.repositories.Scans;
import java.util.List;
import java.util.NoSuchElementException;
import org.springframework.stereotype.Service;

@Service
public class AttestationService {

    private final Scans scans;
    private final GitRepositories repositories;
    private final Findings findings;

    public AttestationService(Scans scans, GitRepositories repositories, Findings findings) {
        this.scans = scans;
        this.repositories = repositories;
        this.findings = findings;
    }

    public InTotoAttestation generateAttestation(long scanId) {
        ScanEntity scan = scans.findById(scanId)
                .orElseThrow(() -> new NoSuchElementException("Scan #" + scanId + " not found."));

        String targetName = "Target #" + (scan.getRepoId() != null ? scan.getRepoId() : scan.getContainerId());
        String targetKind = scan.getRepoId() != null ? "repository" : "container";

        if (scan.getRepoId() != null) {
            RepositoryEntity repo = repositories.findById(scan.getRepoId()).orElse(null);
            if (repo != null) {
                targetName = repo.getName();
            }
        }

        long critical = findings.countByScanIdAndSeverity(scanId, Severity.CRITICAL.wireName());
        long high = findings.countByScanIdAndSeverity(scanId, Severity.HIGH.wireName());
        long medium = findings.countByScanIdAndSeverity(scanId, Severity.MEDIUM.wireName());
        long low = findings.countByScanIdAndSeverity(scanId, Severity.LOW.wireName());

        boolean gatePassed = critical == 0;
        List<String> violations = critical > 0 ? List.of(critical + " unmitigated critical CVEs present") : List.of();

        String sbomHash = scan.getSbom() != null ? Digests.sha256Hex(scan.getSbom()) : null;
        String artifactDigest = sbomHash != null ? sbomHash : Digests.sha256Hex(targetName + ":" + scan.getBranch());

        return InTotoAttestation.create(
                targetName,
                artifactDigest,
                scan.getId(),
                targetKind,
                scan.getBranch(),
                null,
                scan.getCreatedAt(),
                gatePassed,
                violations,
                "Standard Policy",
                new InTotoAttestation.FindingsSummary(critical, high, medium, low, 0L, 0L, scan.getFindingsCount()),
                sbomHash);
    }
}
