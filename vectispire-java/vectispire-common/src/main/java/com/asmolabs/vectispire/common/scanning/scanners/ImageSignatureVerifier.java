package com.asmolabs.vectispire.common.scanning.scanners;

import com.asmolabs.vectispire.common.domain.plugins.PluginSignature;
import com.asmolabs.vectispire.common.scanning.ContainerRun;
import com.asmolabs.vectispire.common.scanning.ContainerRunner;
import com.asmolabs.vectispire.common.scanning.PluginRefusedException;
import com.asmolabs.vectispire.common.scanning.PluginStep;
import com.asmolabs.vectispire.common.scanning.ScannerFailureException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Checks who signed a plugin's image, before it is pulled — {@code cosign verify}, run as a scanner.
 *
 * <p><b>A container, not a library.</b> Sigstore verification in Java means a Fulcio chain, a
 * transparency log's inclusion proof, a TUF client for the trust root and the registry's signature
 * layout — a second implementation of cosign living in the control plane and on every agent, and one
 * more thing to keep in step with how cosign signs. The project already signs its own release with
 * cosign; the executor runs the same tool, pinned by the digest of its multi-architecture index, in
 * the closed shape every scanner gets through {@link ContainerRunner}: not root, a read-only root, no
 * capability, the scanner limits, removed in a {@code finally}. Both executors carry it, and it needs
 * nothing the control plane holds — the signer is in the manifest the agent already fetches.
 *
 * <p><b>The network, and why it is not a plugin's exception.</b> The signature is in the registry, so
 * the verifier has the network, as the matcher has for its database. It is given no file of the
 * target: no tree, no workspace, the public key alone when the manifest declares one. Keyless
 * verification also fetches Sigstore's trust root from its TUF repository; key verification needs the
 * registry and nothing else. Registry credentials are not given to it: an image the registry serves
 * only to an authenticated pull cannot be verified here, and is refused — loudly, never run
 * unverified.
 *
 * <p><b>Verified before the pull, and the verification is the gate.</b> Anything but cosign's exit 0
 * — no signature, another signer, a registry unreachable, a trust root that could not be fetched — is
 * a refusal ({@link PluginRefusedException}, {@code signature_unverified}), with cosign's own words as
 * the reason. A verifier that could not be started at all said nothing about the image: that one is
 * a failure of the step, absent.
 */
public final class ImageSignatureVerifier {

    /**
     * cosign v3.1.3, the version the release workflow signs Vectispire with, by the digest of its
     * multi-architecture index. To refresh: {@code docker buildx imagetools inspect
     * ghcr.io/sigstore/cosign/cosign:<version>}, and move the release workflow's pin with it.
     */
    public static final String COSIGN =
            "ghcr.io/sigstore/cosign/cosign@sha256:9e5c2f2edc34351160407ca3416c61855bdf9403c3c5936e0f0be7fc261611b8";

    /** Where the declared public key is mounted, read-only, alone. */
    static final String KEY_MOUNT = "/trust/cosign.pub";

    /** A registry round trip and a trust root: minutes would be a hang, not a verification. */
    static final Duration TIMEOUT = Duration.ofMinutes(2);

    private final ContainerRunner runner;

    public ImageSignatureVerifier(ContainerRunner runner) {
        this.runner = runner;
    }

    /**
     * @param reference the image as it will be pulled — relocated to the mirror if there is one, which
     *     must then carry the signatures too ({@code cosign copy} does)
     * @param keyDirectory where the public key is written, a directory of the workspace no plugin sees
     * @param cosign the verifier's image, relocated like the plugin's
     * @throws ScannerFailureException when the signature is not verified, in cosign's words
     */
    public void verify(String reference, PluginSignature signature, Path keyDirectory, String owner, String label,
            String cosign) {
        List<String> command = new ArrayList<>();
        command.add("verify");
        List<ContainerRun.Mount> mounts = new ArrayList<>();
        switch (signature.form()) {
            case KEYLESS -> {
                // `--flag=value`, one argv entry each: a value can never be read as another flag.
                command.add("--certificate-identity=" + signature.identity());
                command.add("--certificate-oidc-issuer=" + signature.issuer());
            }
            case KEY -> {
                Path key = keyDirectory.resolve("cosign.pub");
                try {
                    Files.createDirectories(keyDirectory);
                    Files.writeString(key, signature.publicKey(), StandardCharsets.US_ASCII);
                } catch (IOException unwritable) {
                    throw ScannerFailureException.of(label, "The signer's key could not be handed to the verifier: "
                            + unwritable.getMessage());
                }
                mounts.add(ContainerRun.Mount.readOnly(key.toString(), KEY_MOUNT));
                command.add("--key=" + KEY_MOUNT);
                // The key is the trust root; the log would only publish the internal image's name.
                command.add("--insecure-ignore-tlog=true");
            }
        }
        command.add(reference);

        ContainerRun run = ContainerRun.of(cosign, command, mounts, label + " signature")
                .withNetwork()
                .runningAs(owner)
                .withTimeout(TIMEOUT);
        ContainerRunner.ContainerResult result;
        try {
            result = runner.run(run);
        } catch (ScannerFailureException failure) {
            throw ScannerFailureException.of(label, "Its image's signature could not be checked, so it was not run: "
                    + failure.getMessage());
        }
        if (result.exitCode() != 0) {
            // A refusal, not a crash: cosign ran and did not vouch for the image. Its words say which
            // of "another signer", "no signature" or "the registry did not answer" it was.
            String said = result.stderr() == null ? "" : result.stderr().strip();
            throw new PluginRefusedException(label, PluginStep.Refusal.SIGNATURE_UNVERIFIED, "Its image's signature was "
                    + "not verified against the signer its manifest declares, so it was not run. cosign: "
                    + (said.length() <= 2000 ? said : said.substring(0, 2000)));
        }
    }
}
