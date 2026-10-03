package com.asmolabs.vectispire.common.domain.targets;

import com.asmolabs.vectispire.common.domain.crypto.Digests;
import java.util.Optional;

/**
 * What makes two repository targets the same target: the repository ({@link RepositoryUrl#identity}),
 * the branch and the sub-path.
 *
 * <p><b>The sub-path is part of it.</b> A monorepo filed once per service — {@code services/api},
 * {@code services/billing} — is several targets on purpose: each has its backlog, its owner, its
 * schedule. The same directory filed twice is one target scanned twice, with its triage split between
 * two backlogs that drift apart.
 *
 * <p><b>And so is the branch.</b> {@code main} and a maintained {@code release/2.x} of one repository
 * carry different dependencies and different findings, and an organisation that patches a release line
 * has to see that line's backlog on its own; refusing the second branch would remove the only way to.
 * The branch is compared as git compares it, exactly: {@code Main} and {@code main} are two branches.
 * Discovery (decision 0037) asks a wider question — is this repository present at all, whatever its
 * branch and sub-path — and asks it of {@link RepositoryUrl#identity} alone.
 *
 * @param repository {@link RepositoryUrl#identity} of the URL
 * @param branch as stored — {@code main} when none was given
 * @param subPath as {@link RepositorySubPath#normalize} writes it, empty for the root
 */
public record RepositoryIdentity(String repository, String branch, String subPath) {

    /**
     * The identity of a target, or empty when its URL names no host. Lenient on the branch and the
     * sub-path, which rows written before their rules may hold untrimmed or with a trailing slash.
     */
    public static Optional<RepositoryIdentity> of(String url, String branch, String subPath) {
        return RepositoryUrl.identity(url).map(repository -> new RepositoryIdentity(
                repository, branch == null || branch.isBlank() ? "main" : branch.trim(), lenientSubPath(subPath)));
    }

    /**
     * The value the database holds unique, {@code t_repository.identity_guard}: the SHA-256 of the
     * three parts, fixed at 64 characters whatever their lengths — three columns of 255 characters
     * would not fit one MySQL index, and a null sub-path would escape a composite key on both engines.
     */
    public String guard() {
        return Digests.sha256Fields(repository, branch, subPath);
    }

    private static String lenientSubPath(String subPath) {
        String value = subPath == null ? "" : subPath.trim();
        while (value.endsWith("/")) {
            value = value.substring(0, value.length() - 1);
        }
        return value;
    }
}
