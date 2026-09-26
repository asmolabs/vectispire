package com.asmolabs.vectispire.core.targets;

import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.targets.persistence.Containers;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositories;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The repositories and images as the other modules read them: views, never rows.
 *
 * <p><b>Why one class.</b> Ten modules read the targets' tables through their repositories — a gate
 * listing every target, a report naming a scan's repository, a licence screen naming images, a
 * scorecard reading a tier. Each read is the query it was, answered here with the {@link
 * RepositoryView} or {@link ContainerView} the routes already return, whose components are the
 * entity's property names; the reader's code changes from {@code getName()} to {@code name()}, and
 * nothing else. The module that owns the rows is the only one that sees them (decision 0029).
 *
 * <p><b>Two writes, each one column another module decides.</b> Whether a target is in the certified
 * scope is {@code compliance}'s decision, and a repository's badge token is {@code posture}'s: the
 * columns live on the target's row, and are written here, by the owner, on the deciding module's
 * behalf. Visibility stays the caller's to apply, as it was.
 */
@Service
public class TargetCatalog {

    private final GitRepositories repositories;
    private final Containers containers;

    public TargetCatalog(GitRepositories repositories, Containers containers) {
        this.repositories = repositories;
        this.containers = containers;
    }

    /** Every repository, in the order the table returns them. */
    @Transactional(readOnly = true)
    public List<RepositoryView> repositories() {
        return repositories.findAll().stream().map(RepositoryView::of).toList();
    }

    /** Every image, in the order the table returns them. */
    @Transactional(readOnly = true)
    public List<ContainerView> containers() {
        return containers.findAll().stream().map(ContainerView::of).toList();
    }

    @Transactional(readOnly = true)
    public Optional<RepositoryView> repository(long id) {
        return repositories.findById(id).map(RepositoryView::of);
    }

    @Transactional(readOnly = true)
    public Optional<ContainerView> container(long id) {
        return containers.findById(id).map(ContainerView::of);
    }

    /** The repositories with these identifiers that exist — one query, whatever the count. */
    @Transactional(readOnly = true)
    public List<RepositoryView> repositories(Collection<Long> ids) {
        return repositories.findAllById(ids).stream().map(RepositoryView::of).toList();
    }

    /** The images with these identifiers that exist — one query, whatever the count. */
    @Transactional(readOnly = true)
    public List<ContainerView> containers(Collection<Long> ids) {
        return containers.findAllById(ids).stream().map(ContainerView::of).toList();
    }

    @Transactional(readOnly = true)
    public boolean exists(ScanTarget target) {
        return switch (target) {
            case ScanTarget.Repository repository -> repositories.existsById(repository.id());
            case ScanTarget.Container container -> containers.existsById(container.id());
        };
    }

    /**
     * A repository's published badge token — {@code null} when it has none. Not in {@link
     * RepositoryView}: the token is a bearer capability, readable by whoever holds the badge URL, and
     * the view is what the repository routes return.
     */
    public record BadgeToken(long repositoryId, String token) {}

    /** Empty when the repository does not exist. */
    @Transactional(readOnly = true)
    public Optional<BadgeToken> badgeToken(long repositoryId) {
        return repositories.findById(repositoryId).map(row -> new BadgeToken(row.getId(), row.getBadgeToken()));
    }

    /** The repository published under this token, or empty for a token nobody holds. */
    @Transactional(readOnly = true)
    public Optional<Long> repositoryWithBadge(String token) {
        return repositories.findByBadgeToken(token).map(row -> row.getId());
    }

    /** Stores the token {@code posture} generated, or clears it with {@code null}. */
    @Transactional
    public void setBadgeToken(long repositoryId, String token) {
        repositories.findById(repositoryId).ifPresent(row -> {
            row.setBadgeToken(token);
            repositories.save(row);
        });
    }

    /**
     * Puts one target in or out of the certified scope — {@code compliance}'s decision, on the
     * target's row.
     *
     * @return whether the flag changed, so a caller can stay silent about a no-op; false for a
     *     target that does not exist
     */
    @Transactional
    public boolean setInCertifiedScope(ScanTarget target, boolean inScope) {
        return switch (target) {
            case ScanTarget.Repository repository -> repositories.findById(repository.id())
                    .map(row -> {
                        boolean changed = row.isInCertifiedScope() != inScope;
                        row.setInCertifiedScope(inScope);
                        repositories.save(row);
                        return changed;
                    })
                    .orElse(false);
            case ScanTarget.Container container -> containers.findById(container.id())
                    .map(row -> {
                        boolean changed = row.isInCertifiedScope() != inScope;
                        row.setInCertifiedScope(inScope);
                        containers.save(row);
                        return changed;
                    })
                    .orElse(false);
        };
    }
}
