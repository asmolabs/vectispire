package com.asmolabs.zanshin.common.scanning.scanners;

/**
 * The scanner images, <b>pinned by digest</b>.
 *
 * <p>These images <em>are</em> Zanshin's supply chain: a tool that audits everybody else's
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

    public static final ScannerImages PINNED = new ScannerImages(
            "anchore/syft@sha256:1288ea4c8b38767b4e620c1e312c8cb26b6e887a99b4f07ab6cd19fc6f225026",
            "anchore/grype@sha256:1e71065c0a4cff3e6bd3b8add525ffac4343eb4971694eb90a31cf6d4d3e85db",
            "zricethezav/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f",
            "bridgecrew/checkov@sha256:12a62da01af22654883aee3b9da18ba4297f123f5122663bf65235db37934144",
            "semgrep/semgrep@sha256:bdf7013b2c3634a487671158da77c554f531742326b543a9464d2adf6c433ac8");
}
