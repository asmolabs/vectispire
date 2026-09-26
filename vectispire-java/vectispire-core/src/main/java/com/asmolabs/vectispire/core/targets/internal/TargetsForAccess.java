package com.asmolabs.vectispire.core.targets.internal;

import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.access.GrantableTargets;
import com.asmolabs.vectispire.core.targets.TargetNaming;
import com.asmolabs.vectispire.core.targets.persistence.ContainerRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.ProjectRepository;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** {@code access}'s {@link GrantableTargets}, answered from the rows this domain owns. */
@Service
public class TargetsForAccess implements GrantableTargets {

    private final GitRepositoryRepository repositories;
    private final ContainerRepository containers;
    private final ProjectRepository projects;
    private final TargetNaming naming;

    public TargetsForAccess(GitRepositoryRepository repositories, ContainerRepository containers, ProjectRepository projects, TargetNaming naming) {
        this.repositories = repositories;
        this.containers = containers;
        this.projects = projects;
        this.naming = naming;
    }

    @Override
    public List<TargetGrant> named(List<? extends Grant> grants) {
        return naming.named(grants);
    }

    @Override
    @Transactional(readOnly = true)
    public List<Long> repositoriesIn(Collection<Long> projectIds) {
        return repositories.findIdsByProjectIdIn(projectIds);
    }

    @Override
    @Transactional(readOnly = true)
    public boolean projectExists(long projectId) {
        return projects.existsById(projectId);
    }

    @Override
    @Transactional(readOnly = true)
    public boolean exists(ScanTarget target) {
        return switch (target) {
            case ScanTarget.Repository repository -> repositories.existsById(repository.id());
            case ScanTarget.Container container -> containers.existsById(container.id());
        };
    }

    @Override
    @Transactional(readOnly = true)
    public Labels labels() {
        Map<Long, String> byRepository = new LinkedHashMap<>();
        repositories.findAll().forEach(repository -> byRepository.put(repository.getId(), TargetNaming.of(repository)));
        Map<Long, String> byContainer = new LinkedHashMap<>();
        containers.findAll().forEach(container -> byContainer.put(container.getId(), TargetNaming.of(container)));
        return new Labels(byRepository, byContainer);
    }
}
