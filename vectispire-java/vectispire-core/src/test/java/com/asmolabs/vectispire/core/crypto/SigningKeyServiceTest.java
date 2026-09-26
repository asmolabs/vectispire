package com.asmolabs.vectispire.core.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.crypto.CosignSigner;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.settings.persistence.SettingEntity;
import com.asmolabs.vectispire.core.settings.persistence.SettingRepository;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * The signing key, against the database: whether a signature can still be checked tomorrow.
 *
 * <p>The only test there was signed and verified through the same instance, with no configured key
 * and no restart — the one situation in which both defects were invisible. Without a configured key
 * the key changed at every start; with one, the published half belonged to another, random pair.
 * Each test below builds the service the way a restart or a configured deployment does.
 */
@DisplayName("the document signing key")
class SigningKeyServiceTest extends VectispireContextTest {

    private static final byte[] PAYLOAD = "{\"status\":\"passed\"}".getBytes(StandardCharsets.UTF_8);

    @Autowired
    private SettingRepository settings;

    @Autowired
    private SettingsService settingsService;

    @Autowired
    private EncryptionService encryption;

    @Test
    @DisplayName("survives a restart: a second instance signs with the key the first one stored")
    void survivesARestart() {
        SigningKeyService first = new SigningKeyService("", settingsService, encryption);
        String signature = first.sign(PAYLOAD);

        SigningKeyService afterRestart = new SigningKeyService("", settingsService, encryption);

        assertThat(afterRestart.getKeyId()).isEqualTo(first.getKeyId());
        assertThat(afterRestart.verify(PAYLOAD, signature)).isTrue();
        // Stored encrypted, never as a PEM anybody reading the table could use.
        assertThat(settings.findById(SigningKeyService.STORED_KEY).orElseThrow().getValue())
                .doesNotContain("PRIVATE KEY");
    }

    @Test
    @DisplayName("two instances starting together sign with one key: the second never overwrites the first")
    void twoInstancesAgreeOnOneKey() throws Exception {
        // Forced interleaving: the second instance reads "no key" first, then waits while the first
        // generates, stores and starts signing, and only then generates and stores its own. The
        // store was a merge — the second key replaced the first under a running instance, whose
        // signatures then matched nothing stored.
        java.util.concurrent.CountDownLatch secondHasLooked = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch firstIsSigning = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.atomic.AtomicBoolean looked = new java.util.concurrent.atomic.AtomicBoolean();
        SettingsService slowToStore = org.mockito.Mockito.mock(SettingsService.class,
                org.mockito.Mockito.withSettings().defaultAnswer(org.mockito.AdditionalAnswers.delegatesTo(settingsService)));
        when(slowToStore.internalValue(SigningKeyService.STORED_KEY)).thenAnswer(call -> {
            java.util.Optional<String> seen = settingsService.internalValue(SigningKeyService.STORED_KEY);
            if (looked.compareAndSet(false, true)) {
                secondHasLooked.countDown();
                assertThat(firstIsSigning.await(30, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
            }
            return seen;
        });
        SigningKeyService second = new SigningKeyService("", slowToStore, encryption);
        java.util.concurrent.CompletableFuture<String> secondKey =
                java.util.concurrent.CompletableFuture.supplyAsync(second::getKeyId);

        assertThat(secondHasLooked.await(30, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
        SigningKeyService first = new SigningKeyService("", settingsService, encryption);
        String signature = first.sign(PAYLOAD);
        firstIsSigning.countDown();

        assertThat(secondKey.get(30, java.util.concurrent.TimeUnit.SECONDS)).isEqualTo(first.getKeyId());
        SigningKeyService afterRestart = new SigningKeyService("", settingsService, encryption);
        assertThat(afterRestart.getKeyId()).as("the stored key is the one the first instance signs with")
                .isEqualTo(first.getKeyId());
        assertThat(afterRestart.verify(PAYLOAD, signature)).isTrue();
    }

    @Test
    @DisplayName("with a configured key, the published half is derived from it and verifies what it signs")
    void aConfiguredKeyPublishesItsOwnHalf() {
        KeyPair pair = CosignSigner.generateKeyPair();

        SigningKeyService service = new SigningKeyService(CosignSigner.toPem(pair.getPrivate()), settingsService, encryption);

        // It published the public half of a fresh random pair: nothing it signed ever verified.
        assertThat(service.getPublicKey().getEncoded()).isEqualTo(pair.getPublic().getEncoded());
        assertThat(CosignSigner.verify(PAYLOAD, service.sign(PAYLOAD), CosignSigner.parsePublicKey(service.getPublicKeyPem())))
                .isTrue();
        assertThat(settings.findById(SigningKeyService.STORED_KEY)).isEmpty();
    }

    @Test
    @DisplayName("a configured key that is not P-256 is refused at start, not at the first export")
    void aWrongCurveIsRefused() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp384r1"));
        String p384 = CosignSigner.toPem(generator.generateKeyPair().getPrivate());

        assertThatThrownBy(() -> new SigningKeyService(p384, settingsService, encryption))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("P-256");
    }

    @Test
    @DisplayName("a stored key no ENCRYPTION_KEY can read is refused, and never replaced")
    void anUnreadableKeyIsNotReplaced() {
        SettingEntity row = new SettingEntity();
        row.setKey(SigningKeyService.STORED_KEY);
        row.setValue("v2:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        settings.save(row);

        SigningKeyService service = new SigningKeyService("", settingsService, encryption);

        assertThatThrownBy(() -> service.sign(PAYLOAD))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("cannot be decrypted");
        // A replacement would have made every document already signed unverifiable.
        assertThat(settings.findById(SigningKeyService.STORED_KEY).orElseThrow().getValue())
                .isEqualTo("v2:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    }

    @Test
    @DisplayName("without ENCRYPTION_KEY nothing is signed and nothing is stored")
    void noEncryptionKeyNoSignature() {
        EncryptionService unconfigured = mock(EncryptionService.class);
        when(unconfigured.encrypt(anyString(), anyString())).thenThrow(new MissingEncryptionKeyException());
        when(unconfigured.inspect(any(), any())).thenThrow(new MissingEncryptionKeyException());

        SigningKeyService service = new SigningKeyService("", settingsService, unconfigured);

        assertThatThrownBy(() -> service.sign(PAYLOAD)).isInstanceOf(MissingEncryptionKeyException.class);
        assertThat(settings.findById(SigningKeyService.STORED_KEY)).isEmpty();
    }
}
