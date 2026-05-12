package com.asmolabs.zanshin.repository.controllers;

import com.asmolabs.zanshin.repository.dto.CreateRepositoryDto;
import com.asmolabs.zanshin.repository.dto.CreateVexDecisionDto;
import com.asmolabs.zanshin.repository.entities.Scan;
import com.asmolabs.zanshin.repository.entities.VexDecision;
import com.asmolabs.zanshin.repository.entities.ZanshinRepository;
import com.asmolabs.zanshin.repository.services.RepositoryService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/repository")
@RequiredArgsConstructor
@PreAuthorize("hasAnyRole('ADMIN', 'SUPERUSER')")
public class RepositoryController {

    private final RepositoryService repositoryService;

    @PostMapping
    public ResponseEntity<ZanshinRepository> create(@RequestBody CreateRepositoryDto dto) {
        return ResponseEntity.ok(repositoryService.create(dto));
    }

    @GetMapping
    public ResponseEntity<List<ZanshinRepository>> findAll() {
        return ResponseEntity.ok(repositoryService.findAll());
    }

    @GetMapping("/{id}")
    public ResponseEntity<ZanshinRepository> findOne(@PathVariable Long id) {
        return repositoryService.findOne(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/{id}/scan")
    public ResponseEntity<Scan> triggerScan(@PathVariable Long id) {
        ZanshinRepository repo = repositoryService.findOne(id)
                .orElseThrow(() -> new RuntimeException("Repository not found"));
        return ResponseEntity.ok(repositoryService.triggerScan(id, repo.getUrl(), repo.getBranch(), repo.getSubPath()));
    }

    @GetMapping("/{id}/vex")
    public ResponseEntity<List<VexDecision>> getVexDecisions(@PathVariable Long id) {
        return ResponseEntity.ok(repositoryService.getVexDecisions(id));
    }

    @PostMapping("/{id}/vex")
    public ResponseEntity<VexDecision> upsertVexDecision(@PathVariable Long id, @RequestBody CreateVexDecisionDto dto) {
        return ResponseEntity.ok(repositoryService.upsertVexDecision(id, dto));
    }

    @GetMapping("/{id}/vex/export")
    public ResponseEntity<Map<String, Object>> exportOpenVex(@PathVariable Long id) {
        // Simplified export
        return ResponseEntity.ok(Map.of("message", "Export not fully implemented yet"));
    }
}
