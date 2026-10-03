package com.asmolabs.vectispire.common.domain.forges;

/**
 * Which deployment of a forge a connection speaks to — derived from the address typed, never chosen
 * apart from it, so that the two cannot disagree (decision 0037 §1).
 *
 * <p><b>A cloud edition has a fixed host nobody types</b>: it is reached under {@code PUBLIC_ONLY}, with
 * the runtime's trust store, and the "internal network" and pinned-CA options are refused for it. A
 * self-hosted edition is where an internal network and a private CA are the common case.
 */
public enum ForgeEdition {
    GITHUB_COM(ForgeKind.GITHUB, true, "github.com"),
    GITHUB_DATA_RESIDENCY(ForgeKind.GITHUB, true, "GitHub Enterprise Cloud with data residency"),
    GITHUB_ENTERPRISE_SERVER(ForgeKind.GITHUB, false, "GitHub Enterprise Server"),
    GITLAB_COM(ForgeKind.GITLAB, true, "gitlab.com"),
    GITLAB_SELF_MANAGED(ForgeKind.GITLAB, false, "GitLab self-managed or Dedicated");

    private final ForgeKind kind;
    private final boolean cloud;
    private final String label;

    ForgeEdition(ForgeKind kind, boolean cloud, String label) {
        this.kind = kind;
        this.cloud = cloud;
        this.label = label;
    }

    public ForgeKind kind() {
        return kind;
    }

    /** Whether the vendor runs it: a fixed public host, public CAs, no internal network. */
    public boolean cloud() {
        return cloud;
    }

    /** How a sentence names it. */
    public String label() {
        return label;
    }

    /** The value on the wire: lower case, the constant's name. */
    public String wireName() {
        return name().toLowerCase(java.util.Locale.ROOT);
    }
}
