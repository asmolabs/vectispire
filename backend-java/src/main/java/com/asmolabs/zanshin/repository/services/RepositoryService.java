package com.asmolabs.zanshin.repository.services;

import com.asmolabs.zanshin.repository.dto.CreateRepositoryDto;
import com.asmolabs.zanshin.repository.dto.CreateVexDecisionDto;
import com.asmolabs.zanshin.repository.entities.Scan;
import com.asmolabs.zanshin.repository.entities.VexDecision;
import com.asmolabs.zanshin.repository.entities.ZanshinRepository;
import com.asmolabs.zanshin.repository.repositories.ScanRepository;
import com.asmolabs.zanshin.repository.repositories.VexDecisionRepository;
import com.asmolabs.zanshin.repository.repositories.ZanshinRepositoryRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class RepositoryService {

    private final ZanshinRepositoryRepository repoRepository;
    private final ScanRepository scanRepository;
    private final VexDecisionRepository vexRepository;
    private final ScanProcessor scanProcessor;

    @Transactional
    public ZanshinRepository create(CreateRepositoryDto dto) {
        String subPath = dto.subPath() != null ? dto.subPath() : "";
        
        // Simplified lookup (should be more robust in reality)
        Optional<ZanshinRepository> existing = repoRepository.findAll().stream()
                .filter(r -> r.getUrl().equals(dto.url()) && r.getBranch().equals(dto.branch()) && r.getSubPath().equals(subPath))
                .findFirst();

        ZanshinRepository repo;
        if (existing.isEmpty()) {
            repo = ZanshinRepository.builder()
                    .url(dto.url())
                    .branch(dto.branch())
                    .subPath(subPath)
                    .name(dto.name())
                    .build();
            // Map SSH key if provided
            // repo.setSshKey(...)
            repo = repoRepository.save(repo);
            log.info("Created new repository entry for {}", repo.getName() != null ? repo.getName() : repo.getUrl());
        } else {
            repo = existing.get();
            if (dto.name() != null) repo.setName(dto.name());
            repo = repoRepository.save(repo);
            log.info("Reusing existing repository entry for {}", repo.getName() != null ? repo.getName() : repo.getUrl());
        }

        triggerScan(repo.getId(), repo.getUrl(), repo.getBranch(), repo.getSubPath());
        return repo;
    }

    public Scan triggerScan(Long repositoryId, String repoUrl, String branch, String subPath) {
        ZanshinRepository repo = repoRepository.findById(repositoryId)
                .orElseThrow(() -> new RuntimeException("Repository not found"));

        Scan scan = Scan.builder()
                .branch(branch)
                .subPath(subPath != null ? subPath : repo.getSubPath())
                .status("pending")
                .repository(repo)
                .build();
        
        scan = scanRepository.save(scan);

        // Async execution
        scanProcessor.processScan(scan.getId(), repoUrl, branch, subPath, repo.getSshKey() != null ? repo.getSshKey().getId() : null);
        
        return scan;
    }

    public List<ZanshinRepository> findAll() {
        return repoRepository.findAll();
    }

    public Optional<ZanshinRepository> findOne(Long id) {
        return repoRepository.findById(id);
    }

    @Transactional
    public VexDecision upsertVexDecision(Long repoId, CreateVexDecisionDto dto) {
        ZanshinRepository repo = repoRepository.findById(repoId)
                .orElseThrow(() -> new RuntimeException("Repository not found"));

        Optional<VexDecision> existing = vexRepository.findAll().stream()
                .filter(v -> v.getRepository().getId().equals(repoId) 
                        && v.getVulnerabilityId().equals(dto.vulnerabilityId()) 
                        && v.getPackageName().equals(dto.packageName()))
                .findFirst();

        VexDecision decision;
        if (existing.isPresent()) {
            decision = existing.get();
            decision.setStatus(dto.status());
            decision.setJustification(dto.justification());
            decision.setResponse(dto.response());
            decision.setComment(dto.comment());
        } else {
            decision = VexDecision.builder()
                    .vulnerabilityId(dto.vulnerabilityId())
                    .packageName(dto.packageName())
                    .purl(dto.purl())
                    .status(dto.status())
                    .justification(dto.justification())
                    .response(dto.response())
                    .comment(dto.comment())
                    .repository(repo)
                    .build();
        }

        return vexRepository.save(decision);
    }

    public List<VexDecision> getVexDecisions(Long repoId) {
        return vexRepository.findAll().stream()
                .filter(v -> v.getRepository().getId().equals(repoId))
                .toList();
    }
}
