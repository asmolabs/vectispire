package com.asmolabs.zanshin.container.controllers;

import com.asmolabs.zanshin.container.dto.CreateContainerDto;
import com.asmolabs.zanshin.container.entities.Container;
import com.asmolabs.zanshin.container.services.ContainerService;
import com.asmolabs.zanshin.repository.entities.Scan;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/containers")
@RequiredArgsConstructor
public class ContainerController {

    private final ContainerService containerService;

    @PostMapping
    public ResponseEntity<Container> create(@RequestBody CreateContainerDto dto) {
        return ResponseEntity.ok(containerService.create(dto));
    }

    @GetMapping
    public ResponseEntity<List<Container>> findAll() {
        return ResponseEntity.ok(containerService.findAll());
    }

    @GetMapping("/{id}")
    public ResponseEntity<Container> findOne(@PathVariable Long id) {
        return containerService.findOne(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> remove(@PathVariable Long id) {
        containerService.remove(id);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{id}/scan")
    public ResponseEntity<Scan> triggerScan(@PathVariable Long id) {
        return ResponseEntity.ok(containerService.triggerRescan(id));
    }
}
