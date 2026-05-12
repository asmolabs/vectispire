package com.asmolabs.zanshin.repository.services;

import com.asmolabs.zanshin.mail.services.MailService;
import com.asmolabs.zanshin.notifications.services.TeamsService;
import com.asmolabs.zanshin.repository.entities.Scan;
import com.asmolabs.zanshin.repository.gateways.NotificationGateway;
import com.asmolabs.zanshin.repository.repositories.ScanRepository;
import com.asmolabs.zanshin.settings.services.SettingsService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.TransportConfigCallback;
import org.eclipse.jgit.transport.SshTransport;
import org.eclipse.jgit.transport.sshd.SshdSessionFactory;
import org.eclipse.jgit.transport.sshd.SshdSessionFactoryBuilder;
import org.eclipse.jgit.util.FS;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class ScanProcessor {

    private final ScanRepository scanRepository;
    private final NotificationGateway notificationGateway;
    private final SSHKeyService sshKeyService;
    private final SettingsService settingsService;
    private final MailService mailService;
    private final TeamsService teamsService;
    private final ObjectMapper objectMapper;

    @Async
    public void processScan(Long scanId, String repoUrl, String branch, String subPath, UUID sshKeyId) {
        log.info("Processing scan job for Scan ID {} using JGit & Testcontainers: {} (Branch: {}, Path: {})", scanId, repoUrl, branch, subPath != null ? subPath : "root");

        updateScanStatus(scanId, "scanning");

        Path tempDir = null;
        try {
            tempDir = Files.createTempDirectory("zanshin_scan_" + scanId);
            File workDir = tempDir.toFile();

            // 0. Validate Path
            validatePath(subPath);

            // 1. Clone with JGit
            cloneRepositoryWithJGit(repoUrl, branch, workDir, sshKeyId);

            // 2. Generate SBOM with Syft
            Map<String, Object> sbom = generateSbomWithTestcontainers(workDir, subPath);

            // 3. Scan with Grype
            Map<String, Object> cves = scanSbomWithTestcontainers(workDir, sbom);

            // 4. Summarize
            Map<String, Object> summary = summarizeFindings(cves);

            // 5. Update Scan
            Scan scan = scanRepository.findById(scanId).orElseThrow();
            scan.setStatus("completed");
            scan.setSbom(sbom);
            scan.setCves(cves);
            scan.setSummary(summary);
            scan.setFindingsCount((Integer) summary.get("total"));
            scanRepository.save(scan);

            notificationGateway.sendScanUpdate(scanId, "completed");
            log.info("Scan completed for ID {}", scanId);

        } catch (Exception e) {
            log.error("Scan failed for ID {}: {}", scanId, e.getMessage(), e);
            Scan scan = scanRepository.findById(scanId).orElse(null);
            if (scan != null) {
                scan.setStatus("failed");
                scan.setError(e.getMessage());
                scanRepository.save(scan);
            }
            notificationGateway.sendScanUpdate(scanId, "failed");
        } finally {
            if (tempDir != null) {
                deleteDirectory(tempDir.toFile());
            }
        }
    }

    private void updateScanStatus(Long scanId, String status) {
        Scan scan = scanRepository.findById(scanId).orElseThrow();
        scan.setStatus(status);
        scanRepository.save(scan);
        notificationGateway.sendScanUpdate(scanId, status);
    }

    private void cloneRepositoryWithJGit(String repoUrl, String branch, File workDir, UUID sshKeyId) throws Exception {
        log.info("Cloning {} (branch: {}) using JGit", repoUrl, branch);
        
        var cloneCommand = Git.cloneRepository()
                .setURI(repoUrl)
                .setDirectory(workDir)
                .setBranch(branch)
                .setCloneAllBranches(false)
                .setDepth(1);

        if (sshKeyId != null) {
            String privateKey = sshKeyService.getDecryptedKey(sshKeyId);
            
            // Create a temporary key file for JGit with strict permissions
            java.nio.file.attribute.FileAttribute<java.util.Set<java.nio.file.attribute.PosixFilePermission>> attr = 
                java.nio.file.attribute.PosixFilePermissions.asFileAttribute(java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
            Path keyFile = Files.createTempFile("jgit_key_", "", attr);
            Files.writeString(keyFile, privateKey);
            
            SshdSessionFactory sessionFactory = new SshdSessionFactoryBuilder()
                    .setPreferredAuthentications("publickey")
                    .setHomeDirectory(FS.DETECTED.userHome())
                    .setSshDirectory(new File(FS.DETECTED.userHome(), ".ssh"))
                    .setDefaultKeysProvider(file -> {
                        try {
                            return org.apache.sshd.common.util.security.SecurityUtils.loadKeyPairIdentities(null, null, Files.newInputStream(keyFile), null);
                        } catch (Exception e) {
                            return java.util.Collections.emptyList();
                        }
                    })
                    .build(null);

            cloneCommand.setTransportConfigCallback(transport -> {
                if (transport instanceof SshTransport sshTransport) {
                    sshTransport.setSshSessionFactory(sessionFactory);
                }
            });
            
            try {
                cloneCommand.call();
            } finally {
                Files.deleteIfExists(keyFile);
            }
        } else {
            cloneCommand.call();
        }
    }

    private void validatePath(String path) {
        if (path != null && (path.contains("..") || path.startsWith("/") || path.contains("\\"))) {
            throw new RuntimeException("Chemin invalide : la traversée de répertoire n'est pas autorisée.");
        }
    }

    private Map<String, Object> generateSbomWithTestcontainers(File workDir, String subPath) throws IOException {
        String target = subPath != null && !subPath.isEmpty() ? "/src/" + subPath : "/src";
        log.info("Starting Syft container for {}", target);

        try (GenericContainer<?> syft = new GenericContainer<>(DockerImageName.parse("anchore/syft:latest"))) {
            syft.withFileSystemBind(workDir.getAbsolutePath(), "/src", BindMode.READ_ONLY)
                .withCommand("dir:" + target, "-o", "json")
                .waitingFor(Wait.forLogMessage(".*", 1));
            
            syft.start();
            return objectMapper.readValue(syft.getLogs(), Map.class);
        }
    }

    private Map<String, Object> scanSbomWithTestcontainers(File workDir, Map<String, Object> sbom) throws IOException {
        log.info("Starting Grype container");
        File sbomFile = new File(workDir, "sbom.json");
        objectMapper.writeValue(sbomFile, sbom);

        try (GenericContainer<?> grype = new GenericContainer<>(DockerImageName.parse("anchore/grype:latest"))) {
            grype.withFileSystemBind(workDir.getAbsolutePath(), "/work", BindMode.READ_ONLY)
                .withCommand("sbom:/work/sbom.json", "-o", "json")
                .waitingFor(Wait.forLogMessage(".*", 1));
            
            grype.start();
            return objectMapper.readValue(grype.getLogs(), Map.class);
        }
    }

    private Map<String, Object> summarizeFindings(Map<String, Object> cves) {
        Map<String, Object> summary = new HashMap<>();
        summary.put("critical", 0);
        summary.put("high", 0);
        summary.put("medium", 0);
        summary.put("low", 0);
        summary.put("negligible", 0);
        summary.put("unknown", 0);
        summary.put("total", 0);

        if (cves.containsKey("matches")) {
            Iterable<Map<String, Object>> matches = (Iterable<Map<String, Object>>) cves.get("matches");
            int total = 0;
            for (Map<String, Object> match : matches) {
                Map<String, Object> vuln = (Map<String, Object>) match.get("vulnerability");
                String severity = ((String) vuln.get("severity")).toLowerCase();
                summary.put(severity, (Integer) summary.getOrDefault(severity, 0) + 1);
                total++;
            }
            summary.put("total", total);
        }
        return summary;
    }

    private void deleteDirectory(File directory) {
        File[] files = directory.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isDirectory()) {
                    deleteDirectory(file);
                } else {
                    file.delete();
                }
            }
        }
        directory.delete();
    }
}
