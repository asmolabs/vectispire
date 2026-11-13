package com.asmolabs.vectispire.core.golden;

import com.asmolabs.vectispire.common.domain.crypto.Digests;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The private-key PEM blocks the HTTP suites send — every one invented, none a key: the recorder keeps exactly these
 * literal, recognised by fingerprint, and hides every other private key as {@code «pem:<label>:N»}.
 *
 * <p><b>Why they are recorded as they are.</b> The recorder hid every PEM that was neither a certificate nor a public
 * key, and the replay cannot send a placeholder: an SSH key registered by {@code POST /api/v1/ssh-keys}, the
 * repository bound to it next, the private key pasted where the SIEM collector's CA goes to see it refused — 23
 * recordings of six classes could not be replayed, and stood in {@code golden/deferred/_recording.txt}. A key
 * generated at every run would have stayed hidden for good reason; these never were: each was a literal in its test,
 * the same at every run, and the server reads none as a key (it seals the text, or refuses it). Gathered here, they
 * are named as the fixtures they are, and the recorder can tell them from a key it must hide.
 *
 * <p><b>By fingerprint, never by shape.</b> {@link #isFixture} compares the SHA-256 of the whole block with the
 * fingerprints of the constants below. A real key a test sends tomorrow — or one that differs from these by a
 * character — is still a placeholder. The recordings' credential scan ({@code
 * vectispire-rust/security/recordings.gitleaks.toml}) allows these values and no others; here, each line carries
 * {@code gitleaks:allow}, since side by side the default private-key rule reads from one block to the next.
 *
 * <p>The test that uses one is named beside it; a constant no test uses any more is deleted with its use.
 */
public final class FixturePrivateKeys {

    /** {@code AgentSealingKeyRoutesTest}: the deploy key a repository delivered to an agent is sealed with. */
    public static final String DEPLOY =
            "-----BEGIN DUMMY PRIVATE KEY-----\nzq7-deploy-secret\n-----END DUMMY PRIVATE KEY-----"; // gitleaks:allow

    /** {@code ForgeImportsRoutesTest}: the SSH key an imported repository is cloned with over its SSH URL. */
    public static final String FORGE_IMPORT =
            "-----BEGIN DUMMY PRIVATE KEY-----\nforge-import\n-----END DUMMY PRIVATE KEY-----"; // gitleaks:allow

    /** {@code ClientRequestContractTest}, {@code RemainingContractTest}: a key the contract tests register. */
    public static final String CONTRACT =
            "-----BEGIN DUMMY PRIVATE KEY-----\ntest\n-----END DUMMY PRIVATE KEY-----"; // gitleaks:allow

    /** {@code IntegrationInputBoundsTest}: the valid key beside which a field past its ceiling is a 400. */
    public static final String BOUNDS =
            "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----"; // gitleaks:allow

    /**
     * {@code SiemCollectorCaRoutesTest}: a private key pasted where the collector's CA goes, to see it refused. The
     * first thirty-six bytes of a P-256 PKCS#8 header, the same for every key of the curve: no scalar follows.
     */
    public static final String PASTED_FOR_A_CA =
            "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END PRIVATE KEY-----"; // gitleaks:allow

    private static final Set<String> FINGERPRINTS = List.of(DEPLOY, FORGE_IMPORT, CONTRACT, BOUNDS, PASTED_FOR_A_CA)
            .stream().map(Digests::sha256Hex).collect(Collectors.toUnmodifiableSet());

    private FixturePrivateKeys() {}

    /** Whether this whole PEM block is one of the fixtures above, by the SHA-256 of its exact text. */
    public static boolean isFixture(String block) {
        return FINGERPRINTS.contains(Digests.sha256Hex(block));
    }
}
