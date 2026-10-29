package com.asmolabs.vectispire.common.domain.targets;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

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
 *
 * <p><b>And never Vectispire's own endpoints, listed or not.</b> The Docker daemon, the database
 * and the cluster's API are refused to every other outbound door ({@code OutboundUrlGuard}); a
 * repository URL naming one was cloned from — a request the scanning machine sent to the daemon or
 * the database on a URL's say-so. {@link #reserved} answers that, on the same two occasions.
 *
 * @param reserved why a host and port are one of Vectispire's own endpoints, or empty
 */
public record GitHostAllowlist(List<String> entries, Reserved reserved) {

    /** The question asked of the outbound guard's reserved endpoints. */
    @FunctionalInterface
    public interface Reserved {
        Optional<String> reason(String host, int port);

        Reserved NONE = (host, port) -> Optional.empty();
    }

    public GitHostAllowlist {
        entries = List.copyOf(entries);
        reserved = reserved == null ? Reserved.NONE : reserved;
    }

    public GitHostAllowlist(List<String> entries) {
        this(entries, Reserved.NONE);
    }

    /** The same list, refusing the endpoints {@code reserved} names as well. */
    public GitHostAllowlist refusing(Reserved reserved) {
        return new GitHostAllowlist(entries, reserved);
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

    /**
     * Whether a repository URL may be cloned: never from a reserved endpoint; otherwise always when
     * unrestricted, else by its host.
     */
    public boolean permits(String url) {
        if (reservedReason(url).isPresent()) {
            return false;
        }
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

    private Optional<String> reservedReason(String url) {
        Optional<String> host = RepositoryUrl.host(url);
        java.util.OptionalInt port = RepositoryUrl.port(url);
        if (host.isEmpty() || port.isEmpty()) {
            return Optional.empty();
        }
        return reserved.reason(host.get(), port.getAsInt());
    }

    /** The refusal, naming the list or the endpoint, for the form and the scan's error. */
    public String refusal(String url) {
        Optional<String> endpoint = reservedReason(url);
        if (endpoint.isPresent()) {
            return endpoint.get();
        }
        return "Cloning from " + RepositoryUrl.host(url).orElse("this host") + " is not allowed on this instance; "
                + "allowed hosts: " + String.join(", ", entries) + ".";
    }
}
