package com.asmolabs.zanshin.container.services;

import com.asmolabs.zanshin.container.dto.CreateContainerDto;
import com.asmolabs.zanshin.container.entities.Container;
import com.asmolabs.zanshin.container.repositories.ContainerRepository;
import com.asmolabs.zanshin.repository.entities.Scan;
import com.asmolabs.zanshin.repository.repositories.ScanRepository;
import com.asmolabs.zanshin.repository.services.ScanProcessor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class ContainerService {

    private final ContainerRepository containerRepository;
    private final ScanRepository scanRepository;
    private final ScanProcessor scanProcessor;

    @Transactional
    public Container create(CreateContainerDto dto) {
        String imageName = dto.imageName();
        String tag = dto.tag();

        if (imageName != null && imageName.contains(":")) {
            String[] parts = imageName.split(":");
            imageName = parts[0];
            if (parts.length > 1) {
                tag = parts[1];
            }
        }

        Container container = Container.builder()
                .registry(dto.registry())
                .imageName(imageName)
                .tag(tag != null ? tag : "latest")
                .scanIntervalMinutes(dto.scanIntervalMinutes())
                .scanCron(dto.scanCron())
                .build();

        return containerRepository.save(container);
    }

    public List<Container> findAll() {
        return containerRepository.findAll();
    }

    public Optional<Container> findOne(Long id) {
        return containerRepository.findById(id);
    }

    @Transactional
    public void remove(Long id) {
        containerRepository.deleteById(id);
    }

    @Transactional
    public Scan triggerRescan(Long id) {
        Container container = containerRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Container not found"));

        Scan scan = Scan.builder()
                .container(container)
                .status("pending")
                .branch(container.getTag() != null ? container.getTag() : "latest")
                .subPath("")
                .build();
        
        scan = scanRepository.save(scan);

        // Notify processor
        scanProcessor.processScan(scan.getId(), null, scan.getBranch(), "", null);
        
        return scan;
    }
}
