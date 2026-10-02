package com.asmolabs.vectispire.core.targets;

import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.targets.persistence.ContainerRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
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
 * <p><b>Three writes, each one column another module decides.</b> Whether a target is in the
 * certified scope is {@code compliance}'s decision, a repository's badge token {@code posture}'s, and
 * when the scheduler last considered a target {@code scanning}'s: the columns live on the target's
 * row, and are written here, by the owner, on the deciding module's behalf. Visibility stays the
 * caller's to apply, as it was.
 */
@Service
public class TargetCatalog {

    private final GitRepositoryRepository repositories;
    private final ContainerRepository containers;

    public TargetCatalog(GitRepositoryRepository repositories, ContainerRepository containers) {
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

    /**
     * The repositories with these identifiers that exist, a thousand identifiers per statement.
     *
     * <p>It was one query whatever the count, and the count is a reader's allowance or a backlog's
     * targets, sized by the estate: {@code findAllById} binds one parameter per identifier, and the
     * attack-path overview of a reader granted more than 65,535 repositories failed on PostgreSQL. See
     * {@link #carryingCredentials} for the engines' ceilings.
     */
    @Transactional(readOnly = true)
    public List<RepositoryView> repositories(Collection<Long> ids) {
        List<Long> distinct = ids.stream().filter(java.util.Objects::nonNull).distinct().toList();
        List<RepositoryView> found = new java.util.ArrayList<>();
        for (int from = 0; from < distinct.size(); from += LOOKUP_BATCH) {
            repositories.findAllById(distinct.subList(from, Math.min(from + LOOKUP_BATCH, distinct.size())))
                    .forEach(row -> found.add(RepositoryView.of(row)));
        }
        return List.copyOf(found);
    }

    /**
     * Those of these repositories that are cloned with a credential of their own — an SSH key or an
     * HTTPS token — which an executor in {@code delegated} mode would be handed.
     *
     * <p>The same two columns the dispatcher reads to decide what to send, and nothing more: a
     * repository counted here and not there, or the reverse, is an agent kept from a scan it could
     * run, or one handed a scan whose credential is then withheld.
     *
     * <p><b>Asked in batches</b>, because {@code findAllById} is one {@code in (…)} with a bind
     * parameter per identifier, and the engines stop somewhere: the PostgreSQL driver refuses a
     * statement past 65,535 (measured, with 70,003: "PreparedStatement can have at most 65 535
     * parameters"), and a MySQL server-side statement stops at the same.
     * The claim asks a page at a time, but the figure of the scans nobody can take asks about every
     * waiting repository at once, and an estate is allowed to be large.
     */
    @Transactional(readOnly = true)
    public Set<Long> carryingCredentials(Collection<Long> ids) {
        if (ids.isEmpty()) {
            return Set.of();
        }
        List<Long> distinct = List.copyOf(Set.copyOf(ids));
        Set<Long> carrying = new java.util.HashSet<>();
        for (int from = 0; from < distinct.size(); from += LOOKUP_BATCH) {
            repositories.findAllById(distinct.subList(from, Math.min(from + LOOKUP_BATCH, distinct.size()))).stream()
                    .filter(repository -> repository.getSshKeyId() != null || repository.getHttpsTokenId() != null)
                    .map(RepositoryEntity::getId)
                    .forEach(carrying::add);
        }
        return Set.copyOf(carrying);
    }

    /** How many identifiers one lookup binds: far under every engine's limit. */
    static final int LOOKUP_BATCH = 1_000;

    /** The images with these identifiers that exist, a thousand identifiers per statement — as {@link #repositories}. */
    @Transactional(readOnly = true)
    public List<ContainerView> containers(Collection<Long> ids) {
        List<Long> distinct = ids.stream().filter(java.util.Objects::nonNull).distinct().toList();
        List<ContainerView> found = new java.util.ArrayList<>();
        for (int from = 0; from < distinct.size(); from += LOOKUP_BATCH) {
            containers.findAllById(distinct.subList(from, Math.min(from + LOOKUP_BATCH, distinct.size())))
                    .forEach(row -> found.add(ContainerView.of(row)));
        }
        return List.copyOf(found);
    }

    @Transactional(readOnly = true)
    public boolean exists(ScanTarget target) {
        return switch (target) {
            case ScanTarget.Repository repository -> repositories.existsById(repository.id());
            case ScanTarget.Container container -> containers.existsById(container.id());
        };
    }

    /**
     * Records that the scheduler considered the target at {@code at} — {@code scanning}'s tick, on the
     * target's row, in the tick's transaction.
     *
     * <p>A targeted update rather than a save of a row read at the top of the tick, which would write
     * back whatever an operator changed on the settings screen in between (see {@code
     * GitRepositoryRepository.stampScheduled}).
     */
    @Transactional
    public void stampScheduled(ScanTarget target, Instant at) {
        switch (target) {
            case ScanTarget.Repository repository -> repositories.stampScheduled(repository.id(), at);
            case ScanTarget.Container container -> containers.stampScheduled(container.id(), at);
        }
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
     * What putting a target in or out of the certified scope did.
     *
     * <p><b>Three outcomes, not a boolean.</b> A {@code false} used to mean both "already so" and
     * "no such target", so the route answered 200 for an id nobody had registered — a write to
     * nothing reported as done. The caller refuses an absent one as a route refuses a hidden one.
     */
    public enum ScopeChange {
        CHANGED,
        UNCHANGED,
        ABSENT
    }

    /**
     * Puts one target in or out of the certified scope — {@code compliance}'s decision, on the
     * target's row.
     */
    @Transactional
    public ScopeChange setInCertifiedScope(ScanTarget target, boolean inScope) {
        return switch (target) {
            case ScanTarget.Repository repository -> repositories.findById(repository.id())
                    .map(row -> {
                        boolean changed = row.isInCertifiedScope() != inScope;
                        row.setInCertifiedScope(inScope);
                        repositories.save(row);
                        return changed ? ScopeChange.CHANGED : ScopeChange.UNCHANGED;
                    })
                    .orElse(ScopeChange.ABSENT);
            case ScanTarget.Container container -> containers.findById(container.id())
                    .map(row -> {
                        boolean changed = row.isInCertifiedScope() != inScope;
                        row.setInCertifiedScope(inScope);
                        containers.save(row);
                        return changed ? ScopeChange.CHANGED : ScopeChange.UNCHANGED;
                    })
                    .orElse(ScopeChange.ABSENT);
        };
    }
}
