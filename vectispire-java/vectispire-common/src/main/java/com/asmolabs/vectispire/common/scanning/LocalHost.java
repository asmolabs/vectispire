package com.asmolabs.vectispire.common.scanning;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * The name this machine gives itself — the first half of every worker's and agent's identity.
 *
 * <p>One copy for the control plane's three workers and the agent, which had one each: an identity
 * read differently in one of them would be a lease owner the others cannot recognise. Here rather
 * than in the domain because asking the resolver is not a calculation.
 */
public final class LocalHost {

    private LocalHost() {}

    /**
     * The host name, or {@code unknown-host} when the machine cannot name itself.
     *
     * <p>Never fails: a host that cannot name itself still has to produce a distinguishable
     * identity, and the random suffix each caller appends carries the whole burden in that case.
     */
    public static String name() {
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (UnknownHostException unknown) {
            return "unknown-host";
        }
    }

    /** {@link #name()}, cut at {@code length} characters, for an identity stored in a bounded column. */
    public static String name(int length) {
        String name = name();
        return name.length() <= length ? name : name.substring(0, length);
    }
}
