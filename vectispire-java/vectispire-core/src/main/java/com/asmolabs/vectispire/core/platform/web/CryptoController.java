package com.asmolabs.vectispire.core.platform.web;

import com.asmolabs.vectispire.common.domain.crypto.CosignSigner;
import com.asmolabs.vectispire.core.access.web.security.RequiresAccount;
import com.asmolabs.vectispire.core.crypto.SigningKeyService;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * REST controller exposing cryptographic signing public keys, signature verification endpoints,
 * and Cosign / Sigstore CLI verification commands.
 */
@RestController
@RequestMapping("/api/v1/crypto")
public class CryptoController {

    private final SigningKeyService signingKeyService;

    public CryptoController(SigningKeyService signingKeyService) {
        this.signingKeyService = signingKeyService;
    }

    @com.asmolabs.vectispire.core.access.web.security.OpenToAnonymous
    @GetMapping(value = "/public-key.pub", produces = "application/x-pem-file")
    public ResponseEntity<String> getPublicKey() {
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"vectispire-signing-key.pub\"")
                .body(signingKeyService.activePublicKeyPem());
    }

    /**
     * @param status {@code ACTIVE} for the key signing now, {@code RETIRED} for one it replaced — whose
     *     documents remain authentic — and {@code REVOKED} for one nothing signed with should be trusted
     * @param activeFrom when the deployment first signed with it; absent when that predates the record
     * @param retiredAt when another key replaced it; absent for the active key
     */
    public record PublishedKeyResponse(
            String keyId, String status, String publicKey, Instant activeFrom, Instant retiredAt) {}

    /**
     * Every key this deployment has signed with, the active one first. A document carries the id of
     * the key that signed it (a DSSE envelope's {@code keyid}, an evidence bundle's public key); the
     * consumer checks it is listed here, and not revoked.
     */
    @com.asmolabs.vectispire.core.access.web.security.OpenToAnonymous
    @GetMapping("/public-keys")
    public List<PublishedKeyResponse> listPublicKeys() {
        return signingKeyService.publishedKeys().stream()
                .map(k -> new PublishedKeyResponse(k.keyId(), k.status().name(), k.publicKeyPem(), k.activeFrom(), k.retiredAt()))
                .toList();
    }

    /** One of those keys by its id, as a PEM file {@code cosign verify-blob --key} reads. */
    @com.asmolabs.vectispire.core.access.web.security.OpenToAnonymous
    @GetMapping(value = "/public-keys/{keyId}.pub", produces = "application/x-pem-file")
    public ResponseEntity<String> getPublicKeyById(@PathVariable String keyId) {
        SigningKeyService.PublishedKey key = signingKeyService.publishedKey(keyId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Signing key not found."));
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"vectispire-signing-key-"
                        + key.keyId().substring(0, 12) + ".pub\"")
                .body(key.publicKeyPem());
    }

    public record VerifyRequest(
            String payload,
            String signature,
            String publicKey) {}

    /**
     * @param keyId the key the signature was checked against — the caller's own when they supplied one
     * @param vectispireKey whether that key is one of Vectispire's signing keys, active or not; a valid
     *     signature under any other key says nothing about Vectispire
     * @param keyStatus {@code ACTIVE}, {@code RETIRED} or {@code REVOKED} when it is one of them; absent
     *     otherwise. A revoked key's signature is never valid.
     */
    public record VerifyResponse(
            boolean valid,
            String keyId,
            boolean vectispireKey,
            String keyStatus,
            String algorithm,
            String message) {}

    @PostMapping(value = "/verify", consumes = MediaType.APPLICATION_JSON_VALUE)
    @RequiresAccount
    public VerifyResponse verifySignature(@RequestBody VerifyRequest request) {
        if (request == null || request.payload() == null || request.signature() == null) {
            return new VerifyResponse(false, null, false, null, CosignSigner.ALGORITHM, "Payload and signature are required.");
        }
        SigningKeyService.Verification result = signingKeyService.verify(
                request.payload().getBytes(StandardCharsets.UTF_8), request.signature(), request.publicKey());
        return new VerifyResponse(result.valid(), result.keyId(), result.vectispireKey(),
                result.keyStatus() == null ? null : result.keyStatus().name(), CosignSigner.ALGORITHM, result.message());
    }

    @GetMapping("/cosign-cli-helper")
    @RequiresAccount
    public Map<String, Object> getCosignCliHelper() {
        return Map.of(
                "keyId", signingKeyService.getKeyId(),
                "keyAlgorithm", "ECDSA_P256",
                "instructions", "Verify artifacts using standard cosign or openssl CLI",
                // `--insecure-ignore-tlog=true` on every cosign command: Vectispire signs with its own
                // key and uploads nothing to Rekor, and cosign 2 looks the signature up in the
                // transparency log by default — without the flag each of these answered "signature not
                // found in transparency log" for every export ever produced, and an auditor following
                // them concluded the document was not signed.
                "commands", Map.of(
                        "cosignVerifyManifest", "cosign verify-blob --key vectispire-signing-key.pub --insecure-ignore-tlog=true --signature manifest.json.sig manifest.json",
                        "cosignVerifyVex", "cosign verify-blob --key vectispire-signing-key.pub --insecure-ignore-tlog=true --signature 05_openvex_advisory.json.sig 05_openvex_advisory.json",
                        "cosignVerifyCycloneDx", "cosign verify-blob --key vectispire-signing-key.pub --insecure-ignore-tlog=true --signature 08_cyclonedx_1_5_vex.json.sig 08_cyclonedx_1_5_vex.json",
                        "opensslVerify", "openssl dgst -sha256 -verify vectispire-signing-key.pub -signature <(base64 -d manifest.json.sig) manifest.json"
                )
        );
    }
}
