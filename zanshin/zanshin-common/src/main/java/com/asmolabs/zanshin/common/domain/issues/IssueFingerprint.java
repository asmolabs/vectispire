package com.asmolabs.zanshin.common.domain.issues;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * An issue's identity across scans.
 *
 * <p><b>The most critical data contract in the system.</b> Two successive scans produce raw
 * findings with no identity; it is this fingerprint that decides whether what the scanner
 * just saw is <em>the same issue as yesterday</em> — with its history, its occurrence count
 * and above all its triage decision — or a new one.
 *
 * <p>A one-byte divergence fails nowhere: it simply means no fingerprint computed here
 * matches the ones already in the database. On the first scan after a switchover the whole
 * existing backlog would be resolved ("these issues are no longer seen") and recreated from
 * scratch, <b>triage lost</b> — every argued {@code not_affected} decision, every VEX
 * justification, every review date. With no error, no log entry, and a dashboard that looks
 * normal.
 *
 * <p>That risk is exactly why this class is a port and not a rewrite, and why
 * {@code IssueFingerprintTest} runs the same golden vectors the Python and NestJS
 * implementations run — the same file, not a copy of it.
 *
 * <h2>What goes in, and what does not</h2>
 *
 * <pre>SHA-256("repo:{id}|{type}|{identifier}|{purl or name}|{path}")</pre>
 *
 * <p><b>Deliberately excluded:</b>
 *
 * <ul>
 *   <li><b>the package version</b> — an outdated dependency that stays outdated across three
 *       version bumps is one issue with a history, not three; otherwise a triage decision
 *       would evaporate on every patch release;
 *   <li><b>whether the dependency is direct or transitive</b> — a dependency that goes from
 *       direct to transitive is the same issue seen differently;
 *   <li><b>the line number</b> — a secret that moves down three lines is the same secret.
 * </ul>
 *
 * <p>The purl takes precedence over the package name because it is the ecosystem-qualified
 * identity; falling back to the name keeps findings that have no purl — secrets, IaC,
 * licenses — fingerprintable.
 *
 * <h2>A weakness reproduced on purpose</h2>
 *
 * <p>The separator is a vertical bar, not the audit chain's NUL byte. A file path containing
 * {@code |} can therefore, in principle, imitate a field boundary and produce a collision.
 * <b>Do not fix this here.</b> Changing the separator would change every fingerprint already
 * stored, which is precisely the scenario described above. If it is ever fixed, it will be by
 * a migration that recomputes the stored fingerprints inside the same transaction.
 */
public final class IssueFingerprint {

    private IssueFingerprint() {}

    /**
     * @param repoId mutually exclusive with {@code containerId}: an issue belongs to one target
     */
    public record Input(
            Integer repoId,
            Integer containerId,
            String findingType,
            String identifier,
            String purl,
            String packageName,
            String filePath) {}

    public static String build(Input input) {
        // Presence decides, not truthiness. A `repoId` of 0 names repository 0, not the
        // absence of a repository — so this is a null check and not an emptiness test, which
        // would file that case as a container.
        String target = input.repoId() != null
                ? "repo:" + input.repoId()
                : "container:" + input.containerId();

        String joined = String.join(
                "|",
                target,
                orEmpty(input.findingType()),
                orEmpty(input.identifier()),
                // `purl or package_name or ""`: an *empty* purl falls back to the package
                // name, matching the original's `||`.
                firstNonEmpty(input.purl(), input.packageName()),
                orEmpty(input.filePath()));

        return sha256Hex(joined);
    }

    /**
     * Empty, not blank.
     *
     * <p>The original tests emptiness the way JavaScript's {@code ||} does: {@code ""} is
     * absent, {@code " "} is a value. Using {@code isBlank()} here would look tidier and would
     * change the fingerprint of every finding whose path or identifier is a single space —
     * silently, and only for those rows.
     */
    private static String orEmpty(String value) {
        return value == null ? "" : value;
    }

    private static String firstNonEmpty(String first, String second) {
        if (first != null && !first.isEmpty()) {
            return first;
        }
        return second == null ? "" : second;
    }

    private static String sha256Hex(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is mandated by the platform; if it is missing the JRE is broken.
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
