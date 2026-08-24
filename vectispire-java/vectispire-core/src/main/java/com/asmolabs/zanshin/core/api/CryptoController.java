package com.asmolabs.zanshin.core.api;

import com.asmolabs.zanshin.core.api.security.RequiresAccount;
import com.asmolabs.zanshin.core.services.SigningKeyService;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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

    @com.asmolabs.zanshin.core.api.security.OpenToAnonymous
    @GetMapping(value = "/public-key.pub", produces = "application/x-pem-file")
    public ResponseEntity<String> getPublicKey() {
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"zanshin-signing-key.pub\"")
                .body(signingKeyService.getPublicKeyPem());
    }

    public record VerifyRequest(
            String payload,
            String signature,
            String publicKey) {}

    public record VerifyResponse(
            boolean valid,
            String keyId,
            String algorithm,
            String message) {}

    @PostMapping(value = "/verify", consumes = MediaType.APPLICATION_JSON_VALUE)
    @RequiresAccount
    public VerifyResponse verifySignature(@RequestBody VerifyRequest request) {
        if (request == null || request.payload() == null || request.signature() == null) {
            return new VerifyResponse(false, null, "SHA256withECDSA", "Payload and signature are required.");
        }

        byte[] payloadBytes = request.payload().getBytes(StandardCharsets.UTF_8);
        boolean valid = signingKeyService.verify(payloadBytes, request.signature(), request.publicKey());

        return new VerifyResponse(
                valid,
                signingKeyService.getKeyId(),
                "SHA256withECDSA",
                valid ? "Signature valid and authentic." : "Signature verification failed or signature does not match payload.");
    }

    @GetMapping("/cosign-cli-helper")
    @RequiresAccount
    public Map<String, Object> getCosignCliHelper() {
        return Map.of(
                "keyId", signingKeyService.getKeyId(),
                "keyAlgorithm", "ECDSA_P256",
                "instructions", "Verify artifacts using standard cosign or openssl CLI",
                "commands", Map.of(
                        "cosignVerifyManifest", "cosign verify-blob --key zanshin-signing-key.pub --signature manifest.json.sig manifest.json",
                        "cosignVerifyVex", "cosign verify-blob --key zanshin-signing-key.pub --signature 05_openvex_advisory.json.sig 05_openvex_advisory.json",
                        "cosignVerifyCycloneDx", "cosign verify-blob --key zanshin-signing-key.pub --signature 08_cyclonedx_1_5_vex.json.sig 08_cyclonedx_1_5_vex.json",
                        "opensslVerify", "openssl dgst -sha256 -verify zanshin-signing-key.pub -signature <(base64 -d manifest.json.sig) manifest.json"
                )
        );
    }
}
