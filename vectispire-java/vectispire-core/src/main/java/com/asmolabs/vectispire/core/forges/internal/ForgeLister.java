package com.asmolabs.vectispire.core.forges.internal;

import com.asmolabs.vectispire.common.domain.forges.DiscoveredRepository;
import com.asmolabs.vectispire.common.domain.forges.ForgeKind;
import com.asmolabs.vectispire.core.outbound.OutboundPager;
import java.util.List;
import java.util.Map;

/**
 * One forge's listing of namespaces and repositories (decision 0037 §3), behind the interface the discovery is
 * written against: the job, the snapshot and its comparison are written once, each adapter maps. GitLab's is lot
 * D3's; GitHub's is D4's.
 *
 * <p><b>A namespace the token cannot read is not a failed run</b> (§3): where a forge lists per namespace, a 403 on
 * one of them is {@link Listing#unreadable}, and the run goes on with the others. Where a forge withholds
 * namespaces without naming them, {@link Listing#namespacesIncomplete} says so. Either way the run marks none of
 * the repositories it could not see gone — a refusal is not an absence.
 *
 * <p><b>Every request goes through the {@link OutboundPager} the listing hands out</b> — opened on the
 * connection's API origin, with the run's deadline, its rate-limit bound and its lease renewal — and never
 * through a client of the adapter's own.
 */
public interface ForgeLister {

    ForgeKind kind();

    /**
     * Lists, writing into {@code listing} as it goes, page by page. The pager's exceptions — a page on another
     * origin, a long rate limit, the deadline, a forge that does not answer — pass through untouched: the
     * discovery reads each.
     *
     * @throws ForgeListingException a status that ends the run: a rejected token, a listing refused
     */
    void list(Listing listing);

    /** What a listing writes to, and where its requests come from. */
    interface Listing {

        ForgeClient.Target target();

        /** The connection's token, decrypted for this run alone. */
        String token();

        /** A pager on the connection's API origin, carrying {@code credential} — the forge's own header. */
        OutboundPager pager(Map<String, String> credential);

        /** A namespace seen; counted once whatever the number of times it is named. */
        void namespace(String path);

        /**
         * A namespace the token could not read: recorded on the run with the reason, counted as seen, and none of
         * its repositories marked gone by this run. What was read of it before the refusal is kept.
         */
        void unreadable(String path, String reason);

        /**
         * The forge withheld namespaces without naming them — or would not say which namespaces the token sees at
         * all: recorded on the run with the reason, and this run marks gone only repositories of the namespaces it
         * read.
         */
        void namespacesIncomplete(String reason);

        /**
         * A page of repositories, kept in the snapshot and compared with it.
         *
         * @throws RepositoryBoundReached once the run's bound is reached — what fitted under it is kept
         */
        void repositories(List<DiscoveredRepository> page);

        /**
         * The repositories, among those this run listed, whose language is worth one more request: new ones, and
         * those active since the language was last read.
         */
        List<String> languagesWanted();

        /** A repository's main language, or {@code null} when the forge would not say. */
        void language(String forgeId, String language);
    }

    /** The run's repository bound was reached. */
    final class RepositoryBoundReached extends RuntimeException {

        private static final long serialVersionUID = 1L;

        public RepositoryBoundReached(String message) {
            super(message);
        }
    }
}
