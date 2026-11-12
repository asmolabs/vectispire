package com.asmolabs.vectispire.core.forges.internal;

import com.asmolabs.vectispire.common.domain.forges.BranchPresence;
import com.asmolabs.vectispire.core.outbound.OutboundJson;
import com.asmolabs.vectispire.core.outbound.OutboundPager;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.BiFunction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * The branch names a discovery asks every repository about — {@code main}, {@code master} and {@code develop} unless
 * {@code vectispire.forges.discovery.tracked-branches} names others — so that the selection can filter on them and an
 * import create one target per branch (decision 0037 §3–5).
 *
 * <p><b>A short list, checked at start.</b> Each name costs up to one request per repository the discovery asks, a
 * repository being asked when it is new or active since its branches were last read: ten names at most. A name that
 * could not be a branch an import names — empty, with whitespace or a comma, or the word {@code default}, which names
 * the default branch whatever it is called — stops the start rather than being skipped: a configuration that is
 * silently narrowed reads as "no repository has trunk".
 */
@Component
public class TrackedBranches {

    private static final Logger log = LoggerFactory.getLogger(TrackedBranches.class);

    private final List<String> names;

    public TrackedBranches(@Value("${vectispire.forges.discovery.tracked-branches:main,master,develop}") List<String> configured) {
        Set<String> distinct = new LinkedHashSet<>();
        for (String raw : configured == null ? List.<String>of() : configured) {
            String name = raw == null ? "" : raw.trim();
            String refusal = BranchPresence.refusal(name);
            if (refusal != null) {
                throw new IllegalStateException("vectispire.forges.discovery.tracked-branches: " + refusal + ".");
            }
            distinct.add(name);
        }
        if (distinct.size() > BranchPresence.MAX_TRACKED) {
            throw new IllegalStateException("vectispire.forges.discovery.tracked-branches names " + distinct.size()
                    + " branches; at most " + BranchPresence.MAX_TRACKED + ", each costing a request per repository.");
        }
        this.names = List.copyOf(distinct);
    }

    /** The names, in the configured order. */
    public List<String> names() {
        return names;
    }

    /** The names as a snapshot row records what its reading asked ({@link BranchPresence#encode}). */
    public String asked() {
        return BranchPresence.encode(names);
    }

    /**
     * Reads the branches of each repository the listing wants read, asking {@code ask} about each tracked name but
     * the default branch, which the forge already named. One unknown answer makes the repository's whole reading
     * unknown, and its other names are not asked: nothing would be stored of them.
     *
     * <p><b>A rate limit, the run's deadline or a forge that stops answering ends the reading, not the run.</b> The
     * branches are read after the listing, which is whole by then; up to {@value BranchPresence#MAX_TRACKED} requests
     * per repository could otherwise turn a discovery of an organisation of thousands into a partial one, run after
     * run, marking nothing gone. The repositories left keep what they had — an outage written as "unknown" would erase
     * what an earlier run read — and are asked at the next run, and the listing is told how many. A refusal of one
     * branch (a 403) is an answer about that repository, and is written as unknown.
     *
     * @param ask a request about one branch of one repository: present, absent or unknown; a rejected token throws
     */
    static void read(ForgeLister.Listing listing, BiFunction<ForgeLister.BranchQuestion, String, BranchPresence.Answer> ask) {
        List<String> tracked = listing.trackedBranches();
        List<ForgeLister.BranchQuestion> wanted = listing.branchesWanted();
        if (tracked.isEmpty()) {
            return;
        }
        for (int done = 0; done < wanted.size(); done++) {
            ForgeLister.BranchQuestion question = wanted.get(done);
            Set<String> present = new TreeSet<>();
            boolean unknown = false;
            try {
                for (String name : tracked) {
                    BranchPresence.Answer answer = name.equals(question.defaultBranch()) ? BranchPresence.Answer.PRESENT
                            : ask.apply(question, name);
                    if (answer == BranchPresence.Answer.UNKNOWN) {
                        unknown = true;
                        break;
                    }
                    if (answer == BranchPresence.Answer.PRESENT) {
                        present.add(name);
                    }
                }
            } catch (OutboundPager.RateLimitedException | OutboundPager.DeadlineReachedException
                    | OutboundJson.OutboundFailureException stopped) {
                int left = wanted.size() - done;
                log.info("Forge discovery: the tracked branches of {} repositories left for the next run ({}).", left,
                        stopped.getMessage());
                listing.branchesLeft(left, switch (stopped) {
                    case OutboundPager.RateLimitedException limited -> "a rate limit longer than the run waits";
                    case OutboundPager.DeadlineReachedException late -> "the run's time bound";
                    default -> "the forge stopped answering";
                });
                return;
            }
            listing.branches(question.forgeId(), unknown ? null : new ArrayList<>(present));
        }
    }
}
