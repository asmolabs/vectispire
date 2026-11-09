package com.asmolabs.vectispire.common.domain.forges;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The oldest server each adapter is written for (decision 0037 §1): the vendors' supported versions when
 * the lot landed. A connection to an older one is refused with the version found, at its creation, rather
 * than failing a discovery later on a field the server does not have.
 */
public final class ForgeVersion {

    /** GitLab 16: the keyset pagination and the token self-inspection the adapter relies on. */
    public static final int GITLAB_MINIMUM_MAJOR = 16;

    /** GitHub Enterprise Server 3.12. */
    public static final int GHES_MINIMUM_MAJOR = 3;
    public static final int GHES_MINIMUM_MINOR = 12;

    private static final Pattern MAJOR_MINOR = Pattern.compile("^\\s*v?(\\d{1,4})\\.(\\d{1,4})");

    private ForgeVersion() {}

    /**
     * Whether a reported version is too old; empty when it could not be read — not refused, since an
     * unreadable version proves nothing, and not stated as supported either.
     */
    public static Optional<Boolean> tooOld(ForgeEdition edition, String reported) {
        if (reported == null) {
            return Optional.empty();
        }
        Matcher version = MAJOR_MINOR.matcher(reported);
        if (!version.find()) {
            return Optional.empty();
        }
        int major = Integer.parseInt(version.group(1));
        int minor = Integer.parseInt(version.group(2));
        return switch (edition) {
            case GITLAB_COM, GITLAB_SELF_MANAGED -> Optional.of(major < GITLAB_MINIMUM_MAJOR);
            case GITHUB_ENTERPRISE_SERVER -> Optional.of(
                    major < GHES_MINIMUM_MAJOR || (major == GHES_MINIMUM_MAJOR && minor < GHES_MINIMUM_MINOR));
            case GITHUB_COM, GITHUB_DATA_RESIDENCY -> Optional.of(false);
        };
    }
}
