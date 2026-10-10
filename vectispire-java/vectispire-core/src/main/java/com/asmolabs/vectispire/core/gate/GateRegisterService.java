package com.asmolabs.vectispire.core.gate;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.paging.RegisterCursor;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.gate.persistence.GateVerdictEntity;
import com.asmolabs.vectispire.core.gate.persistence.GateVerdictRepository;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Limit;
import org.springframework.stereotype.Service;

/**
 * Reading the gate's register: what it has answered, newest first, within an allowance.
 *
 * <p>Writing to the register is {@link GateService#evaluateAndRecord}'s alone; this only reads.
 */
@Service
public class GateRegisterService {

    /** A register is read, not paged through: past a few hundred rows nobody is reading. */
    private static final int MAX_VERDICTS = 500;

    private final GateVerdictRepository verdicts;

    public GateRegisterService(GateVerdictRepository verdicts) {
        this.verdicts = verdicts;
    }

    /**
     * The register newest first, at most {@code limit} rows, whoever may see them: section 09 of the
     * evidence bundle filters by its reader's allowance itself, and says when the cap cut it short.
     * Like the two lookups below, it exists because the register is this module's table.
     */
    public List<GateVerdictView> newest(int limit) {
        return verdicts.findAllByOrderByDecidedAtDesc(Limit.of(limit)).stream().map(GateVerdictView::of).toList();
    }

    /**
     * The last verdict recorded for a repository at or after {@code from} and, when {@code until} is
     * not null, before it — the answer the gate gave about the backlog one scan left.
     *
     * <p>This and {@link #lastForContainer} exist because the register is this module's table: the
     * attestation read it through the repository while the code was packaged by layer. The window
     * is the caller's to choose, and an empty one is an honest "not asked".
     */
    public Optional<GateVerdictView> lastForRepository(Long repoId, Instant from, Instant until) {
        return (until == null
                        ? verdicts.findFirstByRepoIdAndDecidedAtGreaterThanEqualOrderByDecidedAtDesc(repoId, from)
                        : verdicts.findFirstByRepoIdAndDecidedAtGreaterThanEqualAndDecidedAtLessThanOrderByDecidedAtDesc(
                                repoId, from, until))
                .map(GateVerdictView::of);
    }

    /** {@link #lastForRepository}, for a container image. */
    public Optional<GateVerdictView> lastForContainer(Long containerId, Instant from, Instant until) {
        return (until == null
                        ? verdicts.findFirstByContainerIdAndDecidedAtGreaterThanEqualOrderByDecidedAtDesc(containerId, from)
                        : verdicts.findFirstByContainerIdAndDecidedAtGreaterThanEqualAndDecidedAtLessThanOrderByDecidedAtDesc(
                                containerId, from, until))
                .map(GateVerdictView::of);
    }

    /**
     * @param visible the rows of this page the reader may see
     * @param passed how many of {@code visible} passed, and {@code refused} likewise — of this
     *     page, never of the register, which would mean reading the whole of it
     * @param nextCursor where the next page starts, or null when the read reached the end
     */
    public record Page(List<GateVerdictView> visible, long passed, long refused, String nextCursor) {}

    /**
     * One page of the register.
     *
     * <p><b>The limit bounds what is read, not what is returned</b>, and the cursor comes from
     * the rows read rather than the rows returned: a restricted reader's page can be empty while
     * the register still holds rows they may see, and a cursor taken from the visible rows would
     * end the register for them one page in. See the route for the whole argument.
     */
    public Page page(Visibility allowed, int limit, String cursor) {
        int capped = Math.clamp(limit, 1, MAX_VERDICTS);

        // **An unreadable identifier goes back to the first page**, like an absent cursor. The
        // record promises that an unusable cursor reads as "from the beginning"; letting
        // `UUID.fromString` throw here would make it a 400 on a value the client did not compose —
        // it sent back what the server had given it.
        List<GateVerdictEntity> read = read(allowed, RegisterCursor.parse(cursor)
                .flatMap(from -> uuid(from.id()).map(id -> new RegisterCursor(from.at(), id.toString()))), capped);

        // Already within what the reader sees; kept as the second lock it was before the query had one.
        List<GateVerdictEntity> visible = read.stream()
                .filter(row -> allowed.permits(targetOf(row)))
                .toList();

        return new Page(
                visible.stream().map(GateVerdictView::of).toList(),
                visible.stream().filter(GateVerdictEntity::isPassed).count(),
                visible.stream().filter(row -> !row.isPassed()).count(),
                nextCursor(read, capped));
    }

    /**
     * The rows of a page: the whole register for a reader who sees everything, and only the targets a
     * restricted reader may see otherwise — so that the cursor, taken from the last row read, never names
     * a verdict the reader could not have been shown.
     */
    private List<GateVerdictEntity> read(Visibility allowed, Optional<RegisterCursor> after, int limit) {
        if (allowed instanceof Visibility.Everything) {
            return after.map(from -> verdicts.pageAfter(from.at(), UUID.fromString(from.id()), Limit.of(limit)))
                    .orElseGet(() -> verdicts.firstPage(Limit.of(limit)));
        }
        Visibility.Only only = (Visibility.Only) allowed;
        List<Long> repoIds = new java.util.ArrayList<>(List.of(NO_TARGET));
        List<Long> containerIds = new java.util.ArrayList<>(List.of(NO_TARGET));
        for (ScanTarget target : only.targets()) {
            switch (target) {
                case ScanTarget.Repository repository -> repoIds.add(repository.id());
                case ScanTarget.Container container -> containerIds.add(container.id());
            }
        }
        return after.map(from -> verdicts.pageAfterWithin(
                        repoIds, containerIds, from.at(), UUID.fromString(from.id()), Limit.of(limit)))
                .orElseGet(() -> verdicts.firstPageWithin(repoIds, containerIds, Limit.of(limit)));
    }

    /** An identifier no target has, so that neither list is ever empty: `in ()` is not valid everywhere. */
    private static final long NO_TARGET = -1L;

    private static Optional<UUID> uuid(String value) {
        try {
            return Optional.of(UUID.fromString(value));
        } catch (IllegalArgumentException unreadable) {
            return Optional.empty();
        }
    }

    /**
     * Where the next page starts, or nothing when this one reached the end.
     *
     * <p>A short read means the register is exhausted — there is nothing after it to point at. A
     * full one means there may be more, and the cursor names the last row <em>read</em>, whether
     * or not the caller was allowed to see it.
     */
    private static String nextCursor(List<GateVerdictEntity> read, int limit) {
        if (read.size() < limit) {
            return null;
        }
        GateVerdictEntity last = read.getLast();
        return new RegisterCursor(last.getDecidedAt(), last.getId().toString()).encoded();
    }

    private static ScanTarget targetOf(GateVerdictEntity row) {
        return row.getRepoId() != null
                ? new ScanTarget.Repository(row.getRepoId())
                : new ScanTarget.Container(row.getContainerId());
    }
}
