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
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

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

    @Autowired
    private PlatformTransactionManager transactions;

    @Test
    @DisplayName("is created by the first document signed in a read-only transaction, and read back from it")
    void isCreatedInsideAReadOnlyTransaction() {
        SigningKeyService service = new SigningKeyService("", "", settingsService, encryption);
        TransactionTemplate readOnly = new TransactionTemplate(transactions);
        readOnly.setReadOnly(true);

        // The evidence bundle's shape: a read-only transaction that reads first, then signs. The
        // insert joined to it was refused on MySQL and PostgreSQL, and the read-back inside its
        // snapshot would not see the row the insert committed.
        String keyId = readOnly.execute(status -> {
            settings.count();
            return service.getKeyId();
        });

        assertThat(settings.findById(SigningKeyService.STORED_KEY)).isPresent();
        assertThat(new SigningKeyService("", "", settingsService, encryption).getKeyId()).isEqualTo(keyId);
    }

    @Test
    @DisplayName("survives a restart: a second instance signs with the key the first one stored")
    void survivesARestart() {
        SigningKeyService first = new SigningKeyService("", "", settingsService, encryption);
        String signature = first.sign(PAYLOAD);

        SigningKeyService afterRestart = new SigningKeyService("", "", settingsService, encryption);

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
        SigningKeyService second = new SigningKeyService("", "", slowToStore, encryption);
        java.util.concurrent.CompletableFuture<String> secondKey =
                java.util.concurrent.CompletableFuture.supplyAsync(second::getKeyId);

        assertThat(secondHasLooked.await(30, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
        SigningKeyService first = new SigningKeyService("", "", settingsService, encryption);
        String signature = first.sign(PAYLOAD);
        firstIsSigning.countDown();

        assertThat(secondKey.get(30, java.util.concurrent.TimeUnit.SECONDS)).isEqualTo(first.getKeyId());
        SigningKeyService afterRestart = new SigningKeyService("", "", settingsService, encryption);
        assertThat(afterRestart.getKeyId()).as("the stored key is the one the first instance signs with")
                .isEqualTo(first.getKeyId());
        assertThat(afterRestart.verify(PAYLOAD, signature)).isTrue();
    }

    @Test
    @DisplayName("with a configured key, the published half is derived from it and verifies what it signs")
    void aConfiguredKeyPublishesItsOwnHalf() {
        KeyPair pair = CosignSigner.generateKeyPair();

        SigningKeyService service = new SigningKeyService(CosignSigner.toPem(pair.getPrivate()), "", settingsService, encryption);

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

        assertThatThrownBy(() -> new SigningKeyService(p384, "", settingsService, encryption))
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

        SigningKeyService service = new SigningKeyService("", "", settingsService, encryption);

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

        SigningKeyService service = new SigningKeyService("", "", settingsService, unconfigured);

        assertThatThrownBy(() -> service.sign(PAYLOAD)).isInstanceOf(MissingEncryptionKeyException.class);
        assertThat(settings.findById(SigningKeyService.STORED_KEY)).isEmpty();
    }

    @Test
    @DisplayName("a key sealed under a previous ENCRYPTION_KEY is re-sealed under the current one as it loads")
    void aRotatedKeyIsResealed() {
        // Written once and read once per start: nothing else would ever move it, and removing the
        // previous key — as the rotation procedure said once the SSH keys were done — stopped every
        // signature.
        EncryptionService before = new EncryptionService(new com.asmolabs.vectispire.core.crypto.internal.EncryptionProperties(
                java.util.Optional.of("signing-rotation-old-passphrase-0123456789"), java.util.List.of()));
        EncryptionService after = new EncryptionService(new com.asmolabs.vectispire.core.crypto.internal.EncryptionProperties(
                java.util.Optional.of("signing-rotation-new-passphrase-0123456789"),
                java.util.List.of("signing-rotation-old-passphrase-0123456789")));
        KeyPair pair = CosignSigner.generateKeyPair();
        settingsService.storeInternalIfAbsent(SigningKeyService.STORED_KEY,
                before.encrypt(CosignSigner.toPem(pair.getPrivate()), "internal:document_signing_key"));
        SigningKeyService rotated = new SigningKeyService("", "", settingsService, after);
        assertThat(rotated.census()).singleElement().returns(1L, StoreCensus::previousKey);

        // Loaded the way the first document after a restart loads it: inside a read-only transaction.
        TransactionTemplate readOnly = new TransactionTemplate(transactions);
        readOnly.setReadOnly(true);
        String keyId = readOnly.execute(status -> rotated.getKeyId());

        String stored = settings.findById(SigningKeyService.STORED_KEY).orElseThrow().getValue();
        assertThat(after.sealOf(stored, "internal:document_signing_key")).isEqualTo(EncryptionService.Seal.CURRENT);
        assertThat(keyId).isEqualTo(CosignSigner.computeKeyId(pair.getPublic()));
        assertThat(rotated.census()).singleElement().returns(0L, StoreCensus::previousKey).returns(1L, StoreCensus::current);
    }

    @Test
    @DisplayName("a rotation keeps the documents signed before it verifiable, against the key published by its id")
    void aRotationKeepsThePastVerifiable() {
        // The installation's first key: generated and stored, as on every deployment that set none.
        SigningKeyService generated = new SigningKeyService("", "", settingsService, encryption);
        String oldId = generated.getKeyId();
        String before = generated.sign(PAYLOAD);

        // The rotation: a key configured, and a restart.
        KeyPair next = CosignSigner.generateKeyPair();
        SigningKeyService rotated = new SigningKeyService(CosignSigner.toPem(next.getPrivate()), "", settingsService, encryption);
        String after = rotated.sign(PAYLOAD);

        assertThat(rotated.getKeyId()).isNotEqualTo(oldId);
        assertThat(rotated.verify(PAYLOAD, after)).isTrue();
        // The old signature stopped verifying the moment the key changed: it was checked against the
        // active key and nothing else.
        assertThat(rotated.verify(PAYLOAD, before)).isTrue();
        assertThat(rotated.verify(PAYLOAD, before, null))
                .returns(true, SigningKeyService.Verification::valid)
                .returns(oldId, SigningKeyService.Verification::keyId)
                .returns(SigningKeyService.KeyStatus.RETIRED, SigningKeyService.Verification::keyStatus);

        // What a consumer does: fetch the key the document names, and check with it alone.
        assertThat(rotated.publishedKeys()).extracting(SigningKeyService.PublishedKey::keyId, SigningKeyService.PublishedKey::status)
                .containsExactly(
                        org.assertj.core.groups.Tuple.tuple(rotated.getKeyId(), SigningKeyService.KeyStatus.ACTIVE),
                        org.assertj.core.groups.Tuple.tuple(oldId, SigningKeyService.KeyStatus.RETIRED));
        String oldPem = rotated.publishedKey(oldId).orElseThrow().publicKeyPem();
        assertThat(CosignSigner.verify(PAYLOAD, before, CosignSigner.parsePublicKey(oldPem))).isTrue();
        assertThat(CosignSigner.verify(PAYLOAD, after, CosignSigner.parsePublicKey(oldPem))).isFalse();

        // And it survives the next restart, which has nothing left to reconcile.
        SigningKeyService again = new SigningKeyService(CosignSigner.toPem(next.getPrivate()), "", settingsService, encryption);
        assertThat(again.verify(PAYLOAD, before)).isTrue();
        assertThat(again.publishedKeys()).hasSize(2);
    }

    @Test
    @DisplayName("a configured key replaced by another stays published, with the dates it signed between")
    void aConfiguredKeyReplacedStaysPublished() {
        java.time.Instant monday = java.time.Instant.parse("2026-10-26T09:00:00Z");
        java.time.Instant friday = java.time.Instant.parse("2026-10-30T09:00:00Z");
        KeyPair first = CosignSigner.generateKeyPair();
        KeyPair second = CosignSigner.generateKeyPair();
        SigningKeyService onFirst = new SigningKeyService(CosignSigner.toPem(first.getPrivate()), "", settingsService, encryption,
                java.time.Clock.fixed(monday, java.time.ZoneOffset.UTC));
        String signed = onFirst.sign(PAYLOAD);

        SigningKeyService onSecond = new SigningKeyService(CosignSigner.toPem(second.getPrivate()), "", settingsService, encryption,
                java.time.Clock.fixed(friday, java.time.ZoneOffset.UTC));

        SigningKeyService.PublishedKey retired = onSecond.publishedKey(CosignSigner.computeKeyId(first.getPublic())).orElseThrow();
        assertThat(retired.status()).isEqualTo(SigningKeyService.KeyStatus.RETIRED);
        assertThat(retired.activeFrom()).isEqualTo(monday);
        assertThat(retired.retiredAt()).isEqualTo(friday);
        assertThat(onSecond.publishedKey(onSecond.getKeyId()).orElseThrow())
                .returns(friday, SigningKeyService.PublishedKey::activeFrom)
                .returns(null, SigningKeyService.PublishedKey::retiredAt);
        assertThat(onSecond.verify(PAYLOAD, signed)).isTrue();
        // No generated key appeared along the way: both were configured.
        assertThat(settings.findById(SigningKeyService.STORED_KEY)).isEmpty();
    }

    @Test
    @DisplayName("a revoked key stays published as revoked, and nothing signed with it verifies")
    void aRevokedKeyVerifiesNothing() {
        KeyPair compromised = CosignSigner.generateKeyPair();
        String compromisedId = CosignSigner.computeKeyId(compromised.getPublic());
        String signed = new SigningKeyService(CosignSigner.toPem(compromised.getPrivate()), "", settingsService, encryption)
                .sign(PAYLOAD);

        KeyPair next = CosignSigner.generateKeyPair();
        SigningKeyService rotated = new SigningKeyService(
                CosignSigner.toPem(next.getPrivate()), " " + compromisedId.toUpperCase() + " ", settingsService, encryption);

        // Whoever holds a compromised key signs whatever they like with it; a match proves nothing.
        assertThat(rotated.verify(PAYLOAD, signed)).isFalse();
        assertThat(rotated.verify(PAYLOAD, signed, null))
                .returns(false, SigningKeyService.Verification::valid)
                .returns(compromisedId, SigningKeyService.Verification::keyId)
                .returns(SigningKeyService.KeyStatus.REVOKED, SigningKeyService.Verification::keyStatus);
        assertThat(rotated.verify(PAYLOAD, signed, CosignSigner.toPem(compromised.getPublic())))
                .returns(false, SigningKeyService.Verification::valid)
                .returns(true, SigningKeyService.Verification::vectispireKey);
        assertThat(rotated.publishedKey(compromisedId).orElseThrow().status()).isEqualTo(SigningKeyService.KeyStatus.REVOKED);
    }

    @Test
    @DisplayName("a revoked key cannot be the one that signs")
    void aRevokedKeyCannotSign() {
        KeyPair compromised = CosignSigner.generateKeyPair();
        String pem = CosignSigner.toPem(compromised.getPrivate());
        String id = CosignSigner.computeKeyId(compromised.getPublic());

        assertThatThrownBy(() -> new SigningKeyService(pem, id, settingsService, encryption))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("revoked");
    }

    @Test
    @DisplayName("a revoked generated key is refused at start too, not at the first signature")
    void aRevokedGeneratedKeyIsRefusedAtStart() {
        String generatedId = new SigningKeyService("", "", settingsService, encryption).getKeyId();

        // It started, and every export and every route that needed the key answered 500 — a
        // revocation that read as an outage, found by whoever exported first.
        assertThatThrownBy(() -> new SigningKeyService("", generatedId, settingsService, encryption))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("vectispire.signing.revoked-keys");
        // A configured key in front of it signs, and the revoked one stays published as revoked.
        SigningKeyService rotated = new SigningKeyService(
                CosignSigner.toPem(CosignSigner.generateKeyPair().getPrivate()), generatedId, settingsService, encryption);
        assertThat(rotated.publishedKey(generatedId).orElseThrow().status()).isEqualTo(SigningKeyService.KeyStatus.REVOKED);
        // A revocation naming another key leaves the generated one signing.
        assertThat(new SigningKeyService("", "0".repeat(64), settingsService, encryption).getKeyId()).isEqualTo(generatedId);
    }

    @Test
    @DisplayName("through a rolling restart every instance publishes the record's list, and the old one never takes it back")
    void aRollingRestartPublishesOneList() {
        java.time.Instant monday = java.time.Instant.parse("2026-10-26T09:00:00Z");
        java.time.Instant tuesday = java.time.Instant.parse("2026-10-27T09:00:00Z");
        java.time.Instant friday = java.time.Instant.parse("2026-10-30T09:00:00Z");
        KeyPair old = CosignSigner.generateKeyPair();
        KeyPair next = CosignSigner.generateKeyPair();
        String oldId = CosignSigner.computeKeyId(old.getPublic());
        String nextId = CosignSigner.computeKeyId(next.getPublic());
        new SigningKeyService(CosignSigner.toPem(old.getPrivate()), "", settingsService, encryption,
                java.time.Clock.fixed(monday, java.time.ZoneOffset.UTC)).sign(PAYLOAD);
        // Started on Tuesday with the old key, and has signed nothing yet when the rotation comes.
        SigningKeyService notYetRestarted = new SigningKeyService(CosignSigner.toPem(old.getPrivate()), "", settingsService,
                encryption, java.time.Clock.fixed(tuesday, java.time.ZoneOffset.UTC));
        SigningKeyService restarted = new SigningKeyService(CosignSigner.toPem(next.getPrivate()), "", settingsService,
                encryption, java.time.Clock.fixed(friday, java.time.ZoneOffset.UTC));
        restarted.sign(PAYLOAD);

        String signedInTheWindow = notYetRestarted.sign(PAYLOAD);

        // The old instance called its own key active and the new one retired: two lists behind one
        // load balancer, and the answer depended on which instance took the request.
        var expected = java.util.List.of(
                org.assertj.core.groups.Tuple.tuple(nextId, SigningKeyService.KeyStatus.ACTIVE),
                org.assertj.core.groups.Tuple.tuple(oldId, SigningKeyService.KeyStatus.RETIRED));
        for (SigningKeyService instance : java.util.List.of(notYetRestarted, restarted,
                new SigningKeyService(CosignSigner.toPem(next.getPrivate()), "", settingsService, encryption))) {
            assertThat(instance.publishedKeys())
                    .extracting(SigningKeyService.PublishedKey::keyId, SigningKeyService.PublishedKey::status)
                    .containsExactlyElementsOf(expected);
            assertThat(instance.activePublicKeyPem()).isEqualTo(CosignSigner.toPem(next.getPublic()));
        }
        // What the old instance signed in the window is a retired key's, and still authentic: the
        // answer makes no claim that it was signed before the key was replaced.
        assertThat(restarted.verify(PAYLOAD, signedInTheWindow, null))
                .returns(true, SigningKeyService.Verification::valid)
                .returns(oldId, SigningKeyService.Verification::keyId)
                .returns(SigningKeyService.KeyStatus.RETIRED, SigningKeyService.Verification::keyStatus)
                .extracting(SigningKeyService.Verification::message).asString()
                .contains("retired, not revoked").doesNotContain("before that date");
        assertThat(notYetRestarted.verify(PAYLOAD, signedInTheWindow, null).keyStatus())
                .isEqualTo(SigningKeyService.KeyStatus.RETIRED);
    }

    @Test
    @DisplayName("publishes the recorded keys, revocations included, when its own key cannot be loaded")
    void publishesWithoutItsOwnKey() {
        // ENCRYPTION_KEY lost: the generated key cannot be read, and signing is refused. The routes
        // that publish the keys answered 500 with it — the revocation list unreadable when it counts.
        KeyPair recorded = CosignSigner.generateKeyPair();
        KeyPair compromised = CosignSigner.generateKeyPair();
        String recordedId = CosignSigner.computeKeyId(recorded.getPublic());
        String compromisedId = CosignSigner.computeKeyId(compromised.getPublic());
        settingsService.storeInternalIfAbsent(SigningKeyService.KNOWN_KEYS, String.join("\n",
                recordedId + ";2026-10-01T00:00:00Z;-;"
                        + java.util.Base64.getEncoder().encodeToString(recorded.getPublic().getEncoded()),
                compromisedId + ";2026-09-01T00:00:00Z;2026-10-01T00:00:00Z;"
                        + java.util.Base64.getEncoder().encodeToString(compromised.getPublic().getEncoded())));
        settingsService.storeInternalIfAbsent(SigningKeyService.STORED_KEY, "v2:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

        SigningKeyService service = new SigningKeyService("", compromisedId, settingsService, encryption);

        assertThat(service.publishedKeys())
                .extracting(SigningKeyService.PublishedKey::keyId, SigningKeyService.PublishedKey::status)
                .containsExactly(
                        org.assertj.core.groups.Tuple.tuple(recordedId, SigningKeyService.KeyStatus.ACTIVE),
                        org.assertj.core.groups.Tuple.tuple(compromisedId, SigningKeyService.KeyStatus.REVOKED));
        assertThat(service.activePublicKeyPem()).isEqualTo(CosignSigner.toPem(recorded.getPublic()));
        assertThat(service.verify(PAYLOAD, CosignSigner.sign(PAYLOAD, recorded.getPrivate()))).isTrue();
        assertThatThrownBy(() -> service.sign(PAYLOAD)).hasMessageContaining("cannot be decrypted");
    }

    @Test
    @DisplayName("a rotation rolled back makes the first key active again, and the second one retired")
    void aRotationRolledBack() {
        SigningKeyService generated = new SigningKeyService("", "", settingsService, encryption);
        String generatedId = generated.getKeyId();
        KeyPair next = CosignSigner.generateKeyPair();
        String signedByNext = new SigningKeyService(CosignSigner.toPem(next.getPrivate()), "", settingsService, encryption)
                .sign(PAYLOAD);

        // The configured key removed: the stored one signs again.
        SigningKeyService back = new SigningKeyService("", "", settingsService, encryption);

        assertThat(back.getKeyId()).isEqualTo(generatedId);
        assertThat(back.publishedKeys()).extracting(SigningKeyService.PublishedKey::status)
                .containsExactly(SigningKeyService.KeyStatus.ACTIVE, SigningKeyService.KeyStatus.RETIRED);
        assertThat(back.verify(PAYLOAD, signedByNext)).isTrue();
        // Active again from now: a key brought back that still showed its retirement date would tell a
        // consumer it signed nothing after that date.
        assertThat(back.publishedKey(generatedId).orElseThrow().retiredAt()).isNull();
    }

    @Test
    @DisplayName("an installation that generated its key before keys were recorded keeps it published when it rotates")
    void aKeyFromBeforeTheRecordIsPublishedAtTheFirstRotation() {
        // The 0.11 shape: a stored key, signed with, and no record of published keys. The first start
        // after the upgrade may already carry a configured key — the generated one must not vanish.
        KeyPair old = CosignSigner.generateKeyPair();
        settingsService.storeInternalIfAbsent(SigningKeyService.STORED_KEY,
                encryption.encrypt(CosignSigner.toPem(old.getPrivate()), "internal:document_signing_key"));
        String signedBefore = CosignSigner.sign(PAYLOAD, old.getPrivate());

        KeyPair next = CosignSigner.generateKeyPair();
        SigningKeyService rotated = new SigningKeyService(CosignSigner.toPem(next.getPrivate()), "", settingsService, encryption);

        assertThat(rotated.publishedKey(CosignSigner.computeKeyId(old.getPublic())).orElseThrow().status())
                .isEqualTo(SigningKeyService.KeyStatus.RETIRED);
        assertThat(rotated.verify(PAYLOAD, signedBefore)).isTrue();
    }

    @Test
    @DisplayName("a recorded key is known by the id its own key gives, never by the id written beside it")
    void aRecordedIdIsRecomputed() {
        // The record is the row a restored dump brings back: whoever edits it on the way could list a
        // key of theirs under one of Vectispire's ids, and every document they sign would verify as
        // that key's.
        KeyPair honest = CosignSigner.generateKeyPair();
        KeyPair forged = CosignSigner.generateKeyPair();
        String honestId = CosignSigner.computeKeyId(honest.getPublic());
        String claimed = CosignSigner.computeKeyId(CosignSigner.generateKeyPair().getPublic());
        String forgedLine = claimed + ";2026-10-01T00:00:00Z;2026-10-02T00:00:00Z;"
                + java.util.Base64.getEncoder().encodeToString(forged.getPublic().getEncoded());
        settingsService.storeInternalIfAbsent(SigningKeyService.KNOWN_KEYS, String.join("\n",
                honestId + ";2026-09-01T00:00:00Z;2026-10-01T00:00:00Z;"
                        + java.util.Base64.getEncoder().encodeToString(honest.getPublic().getEncoded()),
                forgedLine,
                "not a line at all"));
        String signedByHonest = CosignSigner.sign(PAYLOAD, honest.getPrivate());
        String signedByForged = CosignSigner.sign(PAYLOAD, forged.getPrivate());

        SigningKeyService service = new SigningKeyService(
                CosignSigner.toPem(CosignSigner.generateKeyPair().getPrivate()), "", settingsService, encryption);

        assertThat(service.publishedKey(claimed)).isEmpty();
        assertThat(service.publishedKey(CosignSigner.computeKeyId(forged.getPublic()))).isEmpty();
        assertThat(service.verify(PAYLOAD, signedByForged, null))
                .returns(false, SigningKeyService.Verification::valid)
                .returns(null, SigningKeyService.Verification::keyId)
                .returns(null, SigningKeyService.Verification::keyStatus);
        // One bad line hides itself, not the record: the honest key is still published and verifies.
        assertThat(service.publishedKeys()).extracting(SigningKeyService.PublishedKey::keyId)
                .containsExactly(service.getKeyId(), honestId);
        assertThat(service.verify(PAYLOAD, signedByHonest)).isTrue();
        // And the registration that rewrote the row kept the refused lines for whoever investigates.
        assertThat(settingsService.internalValue(SigningKeyService.KNOWN_KEYS).orElseThrow())
                .contains(forgedLine).contains("not a line at all");
    }
}
