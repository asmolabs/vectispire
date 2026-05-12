package com.asmolabs.zanshin.repository.services;

import com.asmolabs.zanshin.container.entities.Container;
import com.asmolabs.zanshin.container.repositories.ContainerRepository;
import com.asmolabs.zanshin.container.services.ContainerService;
import com.asmolabs.zanshin.repository.entities.ZanshinRepository;
import com.asmolabs.zanshin.repository.repositories.ZanshinRepositoryRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.scheduling.support.CronExpression;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class SchedulerService {

    private final ZanshinRepositoryRepository repoRepository;
    private final RepositoryService repositoryService;
    private final ContainerRepository containerRepository;
    private final ContainerService containerService;

    @Scheduled(fixedRate = 60000) // Every minute
    @Transactional
    public void handleCron() {
        LocalDateTime now = LocalDateTime.now();
        log.debug("Running scheduler at {}", now);

        // 1. Repositories
        List<ZanshinRepository> repos = repoRepository.findAll().stream()
                .filter(r -> (r.getScanIntervalMinutes() != null && r.getScanIntervalMinutes() > 0) || (r.getScanCron() != null && !r.getScanCron().isEmpty()))
                .toList();

        for (ZanshinRepository repo : repos) {
            boolean shouldTrigger = false;

            if (repo.getScanIntervalMinutes() != null && repo.getScanIntervalMinutes() > 0) {
                LocalDateTime lastScan = repo.getLastScheduledScanAt();
                if (lastScan == null || ChronoUnit.MINUTES.between(lastScan, now) >= repo.getScanIntervalMinutes()) {
                    shouldTrigger = true;
                    log.info("Interval trigger for repo {} ({}m)", repo.getUrl(), repo.getScanIntervalMinutes());
                }
            }

            if (!shouldTrigger && repo.getScanCron() != null && !repo.getScanCron().isEmpty()) {
                try {
                    CronExpression cron = CronExpression.parse(repo.getScanCron());
                    LocalDateTime lastScan = repo.getLastScheduledScanAt() != null ? repo.getLastScheduledScanAt() : LocalDateTime.MIN;
                    LocalDateTime lastExecution = cron.prev(now);
                    
                    if (lastExecution != null && lastExecution.isAfter(lastScan)) {
                        shouldTrigger = true;
                        log.info("Cron trigger for repo {} ({})", repo.getUrl(), repo.getScanCron());
                    }
                } catch (Exception e) {
                    log.error("Invalid cron for repo {}: {}", repo.getId(), repo.getScanCron());
                }
            }

            if (shouldTrigger) {
                try {
                    repositoryService.triggerScan(repo.getId(), repo.getUrl(), repo.getBranch(), repo.getSubPath());
                    repo.setLastScheduledScanAt(now);
                    repoRepository.save(repo);
                } catch (Exception e) {
                    log.error("Failed to trigger scheduled scan for repo {}: {}", repo.getId(), e.getMessage());
                }
            }
        }

        // 2. Containers
        List<Container> containers = containerRepository.findAll().stream()
                .filter(c -> (c.getScanIntervalMinutes() != null && c.getScanIntervalMinutes() > 0) || (c.getScanCron() != null && !c.getScanCron().isEmpty()))
                .toList();

        for (Container container : containers) {
            boolean shouldTrigger = false;

            if (container.getScanIntervalMinutes() != null && container.getScanIntervalMinutes() > 0) {
                LocalDateTime lastScan = container.getLastScheduledScanAt();
                if (lastScan == null || ChronoUnit.MINUTES.between(lastScan, now) >= container.getScanIntervalMinutes()) {
                    shouldTrigger = true;
                    log.info("Interval trigger for container {} ({}m)", container.getImageName(), container.getScanIntervalMinutes());
                }
            }

            if (!shouldTrigger && container.getScanCron() != null && !container.getScanCron().isEmpty()) {
                try {
                    CronExpression cron = CronExpression.parse(container.getScanCron());
                    LocalDateTime lastScan = container.getLastScheduledScanAt() != null ? container.getLastScheduledScanAt() : LocalDateTime.MIN;
                    LocalDateTime lastExecution = cron.prev(now);
                    
                    if (lastExecution != null && lastExecution.isAfter(lastScan)) {
                        shouldTrigger = true;
                        log.info("Cron trigger for container {} ({})", container.getImageName(), container.getScanCron());
                    }
                } catch (Exception e) {
                    log.error("Invalid cron for container {}: {}", container.getId(), container.getScanCron());
                }
            }

            if (shouldTrigger) {
                try {
                    containerService.triggerRescan(container.getId());
                    container.setLastScheduledScanAt(now);
                    containerRepository.save(container);
                } catch (Exception e) {
                    log.error("Failed to trigger scheduled scan for container {}: {}", container.getId(), e.getMessage());
                }
            }
        }
    }
}
