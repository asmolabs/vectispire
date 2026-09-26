package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.scorecard.SecurityScorecard;
import com.asmolabs.vectispire.common.domain.scorecard.SvgBadgeGenerator;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.services.audit.AuditLogService;
import com.asmolabs.vectispire.core.services.audit.RequestActor;
import com.asmolabs.vectispire.core.services.shared.RowVisibility;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Optional;
import org.springframework.stereotype.Service;

/**
 * Publishing a repository's grade as a README badge, and serving the badges that were published.
 *
 * <p><b>Publishing is a decision somebody makes</b>, never inherited from the route existing: a
 * published badge says that this repository's posture may be read by anyone holding the link.
 *
 * <p>No transaction of its own: each change is one {@code save}, as it was on the route — and the
 * audit entry after it can open its own without waiting on a parent's lock.
 */
@Service
public class ScorecardBadgeService {

    /** 32 bytes, url-safe, unpadded: it lives in a README's URL and must survive being copied. */
    private static final SecureRandom TOKENS = new SecureRandom();

    private final GitRepositories repositories;
    private final SecurityScorecardService scorecards;
    private final AuditLogService audit;

    public ScorecardBadgeService(
            GitRepositories repositories, SecurityScorecardService scorecards, AuditLogService audit) {
        this.repositories = repositories;
        this.scorecards = scorecards;
        this.audit = audit;
    }

    /**
     * @param token the published token, {@code null} when none is
     * @param changed whether this call published or revoked anything — only a change is audited,
     *     so that asking twice does not write two entries for one decision
     */
    public record Badge(Long repositoryId, String token, boolean changed) {}

    /**
     * The SVG of the repository published under this token, or empty for a token nobody holds.
     *
     * <p><b>An unknown token and a revoked one are the same absence.</b> Telling them apart would
     * say that a repository once had a badge, which is a fact about the estate.
     */
    public Optional<String> publishedSvg(String token) {
        return repositories.findByBadgeToken(token).map(repository -> {
            SecurityScorecard scorecard = scorecards.getRepositoryScorecard(repository.getId()).orElse(null);
            String grade = scorecard != null ? scorecard.grade().getLabel() : "unknown";
            String color = scorecard != null ? scorecard.grade().getBadgeColor() : "#555";
            return SvgBadgeGenerator.generateBadge("security grade", grade, color);
        });
    }

    /** Empty when the repository does not exist; a hidden one is refused before it is looked up. */
    public Optional<Badge> state(long repoId, Visibility allowed) {
        return visible(repoId, allowed).map(repository -> badgeOf(repository, false));
    }

    /**
     * Publishes, or answers the badge already published.
     *
     * <p>Idempotent on purpose: publishing twice returns the same token rather than rotating it
     * and quietly breaking every README that already carries the first one. Rotation is a revoke
     * followed by a publish, which is two deliberate acts.
     *
     * <p>Audited only when it did publish, so the log holds one entry per decision rather than
     * one per click.
     */
    public Optional<Badge> publish(long repoId, Visibility allowed, RequestActor actor) {
        return visible(repoId, allowed).map(repository -> {
            if (repository.getBadgeToken() != null) {
                return badgeOf(repository, false);
            }
            byte[] raw = new byte[32];
            TOKENS.nextBytes(raw);
            repository.setBadgeToken(Base64.getUrlEncoder().withoutPadding().encodeToString(raw));
            repositories.save(repository);
            record(actor, repoId,
                    "Security badge published for repository " + repoId
                            + ": its grade is now readable by anyone holding the badge URL.");
            return badgeOf(repository, true);
        });
    }

    /** Revokes the badge. Every README carrying the old URL starts answering 404. */
    public Optional<Badge> revoke(long repoId, Visibility allowed, RequestActor actor) {
        return visible(repoId, allowed).map(repository -> {
            if (repository.getBadgeToken() == null) {
                return badgeOf(repository, false);
            }
            repository.setBadgeToken(null);
            repositories.save(repository);
            record(actor, repoId, "Security badge revoked for repository " + repoId + ".");
            return badgeOf(repository, true);
        });
    }

    /**
     * The allowance first, then the row — the order the routes have always used.
     *
     * <p>A hidden repository is refused as a hidden target, before anything is read, so that no
     * lookup distinguishes it from one the reader may see.
     */
    private Optional<RepositoryEntity> visible(long repoId, Visibility allowed) {
        RowVisibility.requireVisible(new ScanTarget.Repository(repoId), allowed);
        return repositories.findById(repoId);
    }

    private void record(RequestActor actor, long repoId, String description) {
        audit.record(actor.entry(AuditOperation.BADGE_PUBLISHED, "repository:" + repoId + ":badge", description));
    }

    private static Badge badgeOf(RepositoryEntity repository, boolean changed) {
        return new Badge(repository.getId(), repository.getBadgeToken(), changed);
    }
}
