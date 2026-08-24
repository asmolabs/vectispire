package com.asmolabs.vectispire.common.domain.issues;

import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import java.util.Objects;

/**
 * An issue's identity across scans.
 *
 * <p><b>The most critical data contract in the system.</b> Two successive scans produce raw
 * findings with no identity; this fingerprint decides whether what the scanner just saw is
 * <em>the same issue as yesterday</em> — with its history, its occurrence count and above all
 * its triage decision — or a new one.
 *
 * <p>Getting it wrong fails nowhere. A changed rule resolves the whole existing backlog
 * ("these issues are no longer seen") and recreates it from scratch, <b>triage lost</b> — every
 * argued exemption, every justification, every review date — with no error, no log entry, and
 * a dashboard that looks healthier than before.
 *
 * <p>Which is why the composition below is a data contract from the first scan onwards. It is
 * still editable today only because no instance has run yet.
 *
 * <h2>What goes in, and what does not</h2>
 *
 * <pre>SHA-256(target NUL type NUL identifier NUL (purl or name) NUL path)</pre>
 *
 * <p><b>Deliberately excluded:</b>
 *
 * <ul>
 *   <li><b>the package version</b> — an outdated dependency that stays outdated across three
 *       version bumps is one issue with a history, not three; otherwise a triage decision would
 *       evaporate on every patch release;
 *   <li><b>whether the dependency is direct or transitive</b> — a dependency that goes from
 *       direct to transitive is the same issue seen differently;
 *   <li><b>the line number</b> — a secret that moves down three lines is the same secret.
 * </ul>
 *
 * <p>The purl takes precedence over the package name because it is the ecosystem-qualified
 * identity; falling back to the name keeps findings that have no purl — secrets, IaC, licenses
 * — fingerprintable.
 *
 * <h2>One thing fixed that the original could not fix</h2>
 *
 * <p>The NestJS implementation joined the fields with a vertical bar and carried a note saying
 * the resulting collision — a file path containing {@code |} imitating a field boundary — must
 * <em>not</em> be repaired, because changing the separator rewrites the identity of every issue
 * already stored. That constraint does not apply to an application nobody has run, so the
 * separator here is NUL, which cannot occur in any of the hashed values. See
 * {@link Digests#SEPARATOR}.
 */
public final class IssueFingerprint {

    private IssueFingerprint() {}

    /**
     * @param target which repository or image the finding belongs to
     * @param type the finding type
     * @param identifier the scanner's own identity for the finding — a CVE, a Semgrep rule id
     * @param purl the ecosystem-qualified package identity, when there is one
     * @param packageName the fallback when there is no purl
     * @param filePath where it was found, when the finding is located
     */
    public record Input(
            ScanTarget target,
            FindingType type,
            String identifier,
            String purl,
            String packageName,
            String filePath) {

        public Input {
            Objects.requireNonNull(target, "a finding always belongs to a target");
            Objects.requireNonNull(type, "a finding always has a type");
        }
    }

    public static String of(Input input) {
        return Digests.sha256Fields(
                input.target().fingerprintKey(),
                input.type().wireName(),
                input.identifier(),
                // An *empty* purl falls back to the package name, not just an absent one: an
                // analyzer emitting "" for "no purl here" is common enough that treating the
                // two differently would split one issue into two.
                firstNonEmpty(input.purl(), input.packageName()),
                input.filePath());
    }

    private static String firstNonEmpty(String first, String second) {
        return first != null && !first.isEmpty() ? first : second;
    }
}
