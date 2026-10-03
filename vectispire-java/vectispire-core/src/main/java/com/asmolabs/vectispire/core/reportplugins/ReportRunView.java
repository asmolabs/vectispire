package com.asmolabs.vectispire.core.reportplugins;

import com.asmolabs.vectispire.common.domain.reportplugins.ReportRunReason;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportRunState;
import java.time.Instant;

/**
 * A report run, under the entity's property names (decision 0035 §2) — read by a caller who sees the whole
 * project. The output's bytes are not here: a produced run's package — the file, its signature and its provenance
 * — is downloaded on its own route.
 *
 * @param reason the closed word of a failed or refused run, null otherwise
 * @param detail the sentence of a failed or refused run — the plugin's own words for an exit code, cosign's for a
 *     refusal — null otherwise
 * @param manifestDigest the manifest the run was started with — the plugin's approved one at the claim; null
 *     until claimed
 * @param signerKeySha256 the SHA-256 of the signer's public key, for a manifest signed by key; identity and issuer
 *     for one signed keyless
 * @param outputSha256 the SHA-256 of the file the plugin wrote — kept for a produced run, discarded for an output
 *     refused ({@code output_refused}), whose digest still says which file was refused
 * @param outputMediaType the media type the manifest declared and the check held the file to
 * @param signingKeyId the platform key the package was signed with, by its id; null unless produced
 * @param packageSha256 the SHA-256 of the package a download hands out; null unless produced
 */
public record ReportRunView(
        Long id,
        Long projectId,
        String projectName,
        String pluginId,
        ReportRunState state,
        ReportRunReason reason,
        String detail,
        Instant requestedAt,
        String requestedBy,
        Instant startedAt,
        Instant exportedAt,
        Instant finishedAt,
        String manifestDigest,
        String imageDigest,
        String signerIdentity,
        String signerIssuer,
        String signerKeySha256,
        String exportSchemaVersion,
        String exportSha256,
        Long exportSize,
        Integer exitCode,
        Long outputSize,
        String outputSha256,
        String productVersion,
        String outputMediaType,
        String signingKeyId,
        String packageSha256) {}
