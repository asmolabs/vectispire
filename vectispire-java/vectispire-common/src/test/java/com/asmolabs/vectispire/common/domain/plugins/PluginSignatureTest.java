package com.asmolabs.vectispire.common.domain.plugins;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("a plugin's declared signer")
class PluginSignatureTest {

    /** What `cosign generate-key-pair` writes as cosign.pub: ECDSA P-256. */
    static final String COSIGN_KEY = """
            -----BEGIN PUBLIC KEY-----
            MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhm3H+258usrgldBUFUFN9WFtNT21
            IV1MQgw1S41uz9HTMzDeHNZ9+PsTOW6xznu1CIrVOSLBcsTdCfoM911hVg==
            -----END PUBLIC KEY-----
            """;

    private static final String ED25519 = """
            -----BEGIN PUBLIC KEY-----
            MCowBQYDK2VwAyEAV8CBJG1FhD8INWhSsblqEjZvVvXqYF0J6+u+ZTOHsGM=
            -----END PUBLIC KEY-----
            """;

    private static final String RSA_1024 = """
            -----BEGIN PUBLIC KEY-----
            MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDMjbXpjENwvAAI11YlC2Umh9Im
            h+Ir2WsDBNyOYsGa2nwSLSoKtOYwvyRjmsc/IRVN8daDqC78KdUvoLKHMDAOYX75
            WuixeBt8H8Lt25nQgKIN15IkS6f6pyxst89G+9BuC0J7EOjvTBSbPjNZYda0nig9
            xPDb2yHjArrajWpudwIDAQAB
            -----END PUBLIC KEY-----
            """;

    /** secp256k1 — a curve cosign does not verify with. */
    private static final String K1 = """
            -----BEGIN PUBLIC KEY-----
            MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEPNeae2QktyoGnsYcP6DpG/pgkhk6FzYP
            GioQAYqJ6Ln1stdRucvKjPiW9CKYz//6uBSv9yQ4eNx8Gcs7JqC9Lw==
            -----END PUBLIC KEY-----
            """;

    static final PluginSignature KEYLESS = new PluginSignature(
            "https://github.com/acme/lint/.github/workflows/release.yml@refs/tags/v4.2.0",
            "https://token.actions.githubusercontent.com", null);

    @Test
    @DisplayName("keyless names an identity and its issuer; a key names a PEM public key")
    void forms() {
        assertThat(KEYLESS.validated().form()).isEqualTo(PluginSignature.Form.KEYLESS);
        assertThat(new PluginSignature(null, null, COSIGN_KEY).validated().form()).isEqualTo(PluginSignature.Form.KEY);
        assertThat(new PluginSignature(" ", "", ED25519).validated().form())
                .as("blank fields are absent ones")
                .isEqualTo(PluginSignature.Form.KEY);
    }

    @Test
    @DisplayName("exactly one form: both, neither, or half of keyless is refused")
    void exactlyOne() {
        assertThatThrownBy(() -> new PluginSignature(KEYLESS.identity(), KEYLESS.issuer(), COSIGN_KEY).validated())
                .isInstanceOf(InvalidPluginException.class).hasMessageContaining("not both");
        assertThatThrownBy(() -> new PluginSignature(null, null, null).validated())
                .isInstanceOf(InvalidPluginException.class).hasMessageContaining("not neither");
        assertThatThrownBy(() -> new PluginSignature(KEYLESS.identity(), null, null).validated())
                .isInstanceOf(InvalidPluginException.class).hasMessageContaining("names both");
        assertThatThrownBy(() -> new PluginSignature(null, KEYLESS.issuer(), null).validated())
                .isInstanceOf(InvalidPluginException.class).hasMessageContaining("names both");
    }

    @Test
    @DisplayName("an identity is matched exactly: no space, no control character, an https issuer")
    void exact() {
        assertThatThrownBy(() -> new PluginSignature("a b", KEYLESS.issuer(), null).validated())
                .isInstanceOf(InvalidPluginException.class).hasMessageContaining("matched exactly");
        assertThatThrownBy(() -> new PluginSignature("a\u0000b", KEYLESS.issuer(), null).validated())
                .isInstanceOf(InvalidPluginException.class);
        assertThatThrownBy(() -> new PluginSignature(KEYLESS.identity(), "http://issuer.example", null).validated())
                .isInstanceOf(InvalidPluginException.class).hasMessageContaining("https");
        assertThatThrownBy(() -> new PluginSignature("x".repeat(501), KEYLESS.issuer(), null).validated())
                .isInstanceOf(InvalidPluginException.class).hasMessageContaining("at most");
    }

    @Test
    @DisplayName("a key is one PEM public key of a kind cosign verifies, strong enough to vouch for")
    void keys() {
        assertThatThrownBy(() -> new PluginSignature(null, null, "not a key").validated())
                .isInstanceOf(InvalidPluginException.class);
        assertThatThrownBy(() -> new PluginSignature(null, null, COSIGN_KEY + ED25519).validated())
                .as("two keys are not a signer")
                .isInstanceOf(InvalidPluginException.class).hasMessageContaining("one PEM block");
        assertThatThrownBy(() -> new PluginSignature(null, null,
                        COSIGN_KEY.replace("PUBLIC KEY", "PRIVATE KEY")).validated())
                .as("a private key pasted by mistake is refused, not stored")
                .isInstanceOf(InvalidPluginException.class).hasMessageContaining("one PEM block");
        assertThatThrownBy(() -> new PluginSignature(null, null, RSA_1024).validated())
                .isInstanceOf(InvalidPluginException.class).hasMessageContaining("2048");
        assertThatThrownBy(() -> new PluginSignature(null, null, K1).validated())
                .isInstanceOf(InvalidPluginException.class).hasMessageContaining("P-256");
    }

    @Test
    @DisplayName("a pasted key hashes as typed: line endings and surrounding blanks are not a new manifest")
    void normalised() {
        PluginSignature typed = new PluginSignature(null, null, COSIGN_KEY);
        PluginSignature pasted = new PluginSignature(null, null, "\n  " + COSIGN_KEY.replace("\n", "\r\n") + "\r\n");

        assertThat(pasted.publicKey()).isEqualTo(typed.publicKey());
        assertThat(pasted.digestFields()).isEqualTo(typed.digestFields());
    }

    @Test
    @DisplayName("the signer is in the manifest's digest — and a manifest without one hashes as it did before")
    void digest() {
        PluginManifest unsigned = PluginManifestTest.manifest();

        assertThat(unsigned.digest())
                .as("pinned by value: the digest every stored manifest is keyed by, from before the field existed")
                .isEqualTo("fcead9bd3036bf22242a315233a9b9328e4021d583110dafc55d46b9c1968010");
        String keyless = signed(KEYLESS).digest();
        String key = signed(new PluginSignature(null, null, COSIGN_KEY)).digest();
        String otherKey = signed(new PluginSignature(null, null, ED25519)).digest();
        String otherIdentity = signed(new PluginSignature(KEYLESS.identity() + "x", KEYLESS.issuer(), null)).digest();

        assertThat(Set.of(unsigned.digest(), keyless, key, otherKey, otherIdentity)).hasSize(5);
    }

    @Test
    @DisplayName("the JSON form is public_key in snake_case, and reads back to the same digest")
    void json() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        PluginManifest manifest = signed(new PluginSignature(null, null, COSIGN_KEY));
        String json = mapper.writeValueAsString(manifest);

        assertThat(json).contains("\"signature\"", "\"public_key\"").doesNotContain("\"form\"");
        assertThat(mapper.readValue(json, PluginManifest.class).digest()).isEqualTo(manifest.digest());
        assertThat(mapper.readValue(mapper.writeValueAsString(PluginManifestTest.manifest()), PluginManifest.class)
                        .signature())
                .isNull();
    }

    @Test
    @DisplayName("a manifest refuses a signer that does not validate")
    void manifestValidates() {
        assertThatThrownBy(() -> signed(new PluginSignature("id", null, null)).validated())
                .isInstanceOf(InvalidPluginException.class);
    }

    static PluginManifest signed(PluginSignature signature) {
        PluginManifest m = PluginManifestTest.manifest();
        return new PluginManifest(m.id(), m.name(), m.image(), m.languages(), List.copyOf(m.arguments()), m.output(),
                m.exitCodes(), m.network(), m.networkJustification(), m.timeoutSeconds(), signature);
    }
}
