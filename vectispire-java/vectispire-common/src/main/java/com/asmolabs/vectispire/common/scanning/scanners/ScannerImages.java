package com.asmolabs.vectispire.common.scanning.scanners;

/**
 * The scanner images, <b>pinned by digest</b>.
 *
 * <p>These images <em>are</em> Vectispire's supply chain: a tool that audits everybody else's
 * cannot pull {@code :latest} and run whatever comes down. A digest makes an update a
 * deliberate, reviewable act instead of a change that happens one morning without anyone
 * deciding it.
 *
 * <p>The digests are those of the multi-architecture index, so they still select the right
 * architecture for the host. To refresh one:
 * {@code docker buildx imagetools inspect <image>:latest}.
 *
 * <p>Each image stays overridable, because an operator running an internal mirror needs that —
 * and refusing it would push them to edit the code instead.
 */
public record ScannerImages(String syft, String grype, String gitleaks, String checkov, String semgrep) {


    /**
     * The pinned set with whatever the operator named instead.
     *
     * <p><b>This is the promise above, which nothing implemented.</b> The class documented that
     * "each image stays overridable, because an operator running an internal mirror needs that"
     * — and both construction sites passed {@link #PINNED} straight through, so no deployment
     * could override anything without editing source. An air-gapped or regulated estate pulling
     * from an internal registry could not run Vectispire at all, which is the case the sentence
     * was written for.
     *
     * <p><b>Blank means "keep the pinned one", not "no image".</b> Configuration arrives as empty
     * strings far more often than it arrives absent — an unset environment variable rendered
     * into YAML is {@code ""} — and treating that as a deliberate choice would replace a pinned
     * digest with nothing.
     *
     * <p>An operator overriding an image takes on what the digest was protecting: a tag pulls
     * whatever came down this morning. That is their call to make, and it is exactly why this
     * returns a new record rather than mutating the pinned constant — {@link #PINNED} stays the
     * reference for anyone asking what Vectispire ships with.
     */
    public ScannerImages withOverrides(
            String syft,
            String grype,
            String gitleaks,
            String checkov,
            String semgrep) {
        return new ScannerImages(
                pick(syft, this.syft),
                pick(grype, this.grype),
                pick(gitleaks, this.gitleaks),
                pick(checkov, this.checkov),
                pick(semgrep, this.semgrep));
    }

    private static String pick(String override, String pinned) {
        return override == null || override.isBlank() ? pinned : override.trim();
    }

    public static final ScannerImages PINNED = new ScannerImages(
            "anchore/syft@sha256:1288ea4c8b38767b4e620c1e312c8cb26b6e887a99b4f07ab6cd19fc6f225026",
            "anchore/grype@sha256:1e71065c0a4cff3e6bd3b8add525ffac4343eb4971694eb90a31cf6d4d3e85db",
            "zricethezav/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f",
            "bridgecrew/checkov@sha256:12a62da01af22654883aee3b9da18ba4297f123f5122663bf65235db37934144",
            "semgrep/semgrep@sha256:bdf7013b2c3634a487671158da77c554f531742326b543a9464d2adf6c433ac8");
}
