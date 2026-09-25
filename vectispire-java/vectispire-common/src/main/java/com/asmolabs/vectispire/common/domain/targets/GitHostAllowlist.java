package com.asmolabs.vectispire.common.domain.targets;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * The hosts repositories may be cloned from, when the operator restricts them.
 *
 * <p><b>Empty means every host</b> but the link-local ones, which {@link RepositoryUrl} refuses in
 * every case: a self-hosted forge on the internal network is the ordinary deployment, and refusing
 * private addresses by default would break it. A clone is still a request the scanning machine makes
 * to wherever a URL points, though, and an organisation that knows its forges can say so: listed,
 * only those hosts are cloned from — checked when the URL is entered and again before each scan, so
 * a list tightened later also stops the repositories already registered elsewhere.
 *
 * <p>An entry is a host ({@code gitlab.corp.example}) or a suffix ({@code *.corp.example}, which
 * matches any subdomain but not {@code corp.example} itself). Compared as {@link
 * RepositoryUrl#normalizeHost} writes hosts: case, trailing dot and port do not matter.
 */
public record GitHostAllowlist(List<String> entries) {

    public GitHostAllowlist {
        entries = List.copyOf(entries);
    }

    /** Parses the comma-separated setting; blank is the empty list. */
    public static GitHostAllowlist parse(String configured) {
        return new GitHostAllowlist(Arrays.stream(configured == null ? new String[0] : configured.split(","))
                .map(entry -> entry.trim().toLowerCase(Locale.ROOT))
                .filter(entry -> !entry.isEmpty())
                .map(entry -> entry.startsWith("*.") ? "*." + RepositoryUrl.normalizeHost(entry.substring(2))
                        : RepositoryUrl.normalizeHost(entry))
                .distinct()
                .toList());
    }

    public boolean restricts() {
        return !entries.isEmpty();
    }

    /** Whether a repository URL may be cloned: always when unrestricted, else by its host. */
    public boolean permits(String url) {
        if (!restricts()) {
            return true;
        }
        String host;
        try {
            host = RepositoryUrl.host(url).map(RepositoryUrl::normalizeHost).orElse("");
        } catch (IllegalArgumentException unusable) {
            return false;
        }
        if (host.isEmpty()) {
            return false;
        }
        return entries.stream().anyMatch(entry -> entry.startsWith("*.")
                ? host.endsWith(entry.substring(1))
                : host.equals(entry));
    }

    /** The refusal, naming the list, for the form and the scan's error. */
    public String refusal(String url) {
        return "Cloning from " + RepositoryUrl.host(url).orElse("this host") + " is not allowed on this instance; "
                + "allowed hosts: " + String.join(", ", entries) + ".";
    }
}
