package com.asmolabs.vectispire.core.crypto;

import com.asmolabs.vectispire.common.domain.attestation.DsseEnvelope;
import com.asmolabs.vectispire.common.domain.crypto.CosignSigner;
import com.asmolabs.vectispire.common.domain.crypto.SecretCipher;
import com.asmolabs.vectispire.core.settings.SettingsService;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * The key every Vectispire signature is made with — evidence bundles, VEX, CSAF, CycloneDX, DSSE.
 *
 * <p><b>What was wrong, twice over.</b> Without {@code vectispire.signing.key}, which nothing
 * documented and so every deployment ran without, a fresh pair was generated at each start and kept
 * nowhere: every signature made before a restart stopped verifying, and two instances signed with two
 * keys. With the key set, the published public half came from a <em>different</em>, random pair, so
 * no signature verified at all. A signature nobody can check against the key that is published is not
 * a signature.
 *
 * <p><b>Where the key comes from now.</b>
 * <ol>
 *   <li>{@code vectispire.signing.key} (PEM PKCS#8, P-256), with the public half derived from it.
 *       Set it in a deployment with more than one instance: each instance otherwise needs the same
 *       stored key, see below.
 *   <li>Otherwise the key generated on first use and kept in {@code t_setting}, encrypted under
 *       {@code ENCRYPTION_KEY} and bound to its row. The row is internal: no {@code Setting} names
 *       it, so the catalog never shows it and the settings routes refuse its key.
 * </ol>
 *
 * <p><b>Refused rather than improvised.</b> With no configured key and no {@code ENCRYPTION_KEY},
 * signing throws {@link MissingEncryptionKeyException} (412). With a stored key no configured key can
 * decrypt — {@code ENCRYPTION_KEY} lost, or rotated without keeping the old one — it throws too, and
 * never generates a replacement: a new key would overwrite the one every verifier has learned, and
 * make the documents already handed out unverifiable without a word.
 *
 * <p><b>Rotation keeps the past verifiable.</b> A key is replaced by configuring another one and
 * restarting ({@code docs/en/KEY_ROTATION.md}). Every public half this deployment has signed with is
 * kept in a second internal row, {@value #KNOWN_KEYS}, and published beside the active one: a
 * document signed before the rotation still verifies, here and against the key a consumer fetches by
 * its id. Before that row, replacing the key meant one of two things — the old documents stopped
 * verifying, or the old key had to be kept signing. A key listed in {@code
 * vectispire.signing.revoked-keys} stays published, marked revoked, and nothing signed with it
 * verifies: a compromised key's documents must not keep answering "valid".
 */
@Service
public class SigningKeyService implements SealedStore {

    private static final Logger log = LoggerFactory.getLogger(SigningKeyService.class);

    /** The internal row. Named with a dot so it can never collide with a catalog key. */
    static final String STORED_KEY = "internal.document_signing_key";

    /**
     * Every public half signed with, one line per key: {@code keyId;activeFrom;retiredAt;base64 DER},
     * {@code -} for a time not known. Public keys only, so in the clear: nothing here needs {@code
     * ENCRYPTION_KEY}, and a rotation of that key leaves the row alone.
     */
    static final String KNOWN_KEYS = "internal.document_signing_keys";

    private static final String CONTEXT = "internal:document_signing_key";

    private final String configuredKey;
    private final Set<String> revokedKeyIds;
    private final SettingsService settings;
    private final EncryptionService encryption;
    private final Clock clock;
    /** When this instance started: a key retired after it was retired under this instance, not before it. */
    private final Instant startedAt;

    private volatile KeyMaterial material;
    /** Set once the published list has said why it is published without this instance's key. */
    private volatile boolean warnedUnavailable;
    /** The refused lines already warned about, so that an anonymous caller cannot fill the log with them. */
    private final Set<String> warnedLines = ConcurrentHashMap.newKeySet();
    /** Whether this instance has recorded its key as the active one; nothing is signed before it has. */
    private volatile boolean registered;

    /** Where a known key stands: the one signing now, one that signed before, or one not to trust. */
    public enum KeyStatus { ACTIVE, RETIRED, REVOKED }

    /**
     * A public half this deployment has signed with.
     *
     * @param activeFrom when this deployment first signed with it; null for a key recorded only as
     *     the stored key a configured one replaced, whose first use predates the record
     * @param retiredAt when another key replaced it; null while it is the active one
     */
    public record PublishedKey(
            String keyId, KeyStatus status, String publicKeyPem, Instant activeFrom, Instant retiredAt) {}

    private record Known(String keyId, Instant activeFrom, Instant retiredAt, String der) {
        /**
         * The line, or empty when it cannot be taken as written.
         *
         * <p><b>The id is recomputed from the key, never read.</b> Everything else in this service
         * finds a key by its id — the revocation list, the route that serves one id, the verification
         * that names the key it matched — and the id was the line's first field, trusted as stored.
         * Whoever could write the row (a restored dump edited on the way) could then publish a key
         * under another key's id, or list a revoked key under an id nobody revoked.
         */
        static Optional<Known> parse(String line) {
            String[] f = line.split(";", -1);
            if (f.length != 4) {
                return Optional.empty();
            }
            try {
                String computed = CosignSigner.computeKeyId(CosignSigner.parsePublicKey(f[3]));
                return computed.equals(f[0]) ? Optional.of(new Known(f[0], time(f[1]), time(f[2]), f[3])) : Optional.empty();
            } catch (RuntimeException unreadable) {
                return Optional.empty();
            }
        }

        static Known of(PublicKey key, Instant activeFrom, Instant retiredAt) {
            return new Known(CosignSigner.computeKeyId(key), activeFrom, retiredAt,
                    Base64.getEncoder().encodeToString(key.getEncoded()));
        }

        String line() {
            return keyId + ";" + (activeFrom == null ? "-" : activeFrom) + ";" + (retiredAt == null ? "-" : retiredAt) + ";" + der;
        }

        private static Instant time(String field) {
            return "-".equals(field) ? null : Instant.parse(field);
        }
    }

    private record KeyMaterial(PrivateKey privateKey, PublicKey publicKey, String publicKeyPem, String keyId) {
        static KeyMaterial of(PrivateKey privateKey) {
            PublicKey publicKey = CosignSigner.derivePublicKey(privateKey);
            return new KeyMaterial(privateKey, publicKey, CosignSigner.toPem(publicKey), CosignSigner.computeKeyId(publicKey));
        }
    }

    @Autowired
    public SigningKeyService(
            @Value("${vectispire.signing.key:}") String configuredKey,
            @Value("${vectispire.signing.revoked-keys:}") String revokedKeyIds,
            SettingsService settings,
            EncryptionService encryption) {
        this(configuredKey, revokedKeyIds, settings, encryption, Clock.systemUTC());
    }

    SigningKeyService(String configuredKey, String revokedKeyIds, SettingsService settings, EncryptionService encryption,
            Clock clock) {
        this.configuredKey = configuredKey == null ? "" : configuredKey.trim();
        this.revokedKeyIds = revokedKeyIds == null ? Set.of() : Arrays.stream(revokedKeyIds.split(","))
                .map(String::trim).filter(id -> !id.isEmpty()).map(String::toLowerCase)
                .collect(Collectors.toUnmodifiableSet());
        this.settings = settings;
        this.encryption = encryption;
        this.clock = clock;
        this.startedAt = clock.instant();
        // A configured key is checked at start: a malformed or non-P-256 key is a deployment error,
        // and discovering it on the first evidence export is discovering it too late.
        if (!this.configuredKey.isEmpty()) {
            this.material = refuseRevoked(KeyMaterial.of(CosignSigner.parsePrivateKey(this.configuredKey)));
        } else if (!this.revokedKeyIds.isEmpty()) {
            refuseRevokedStoredKey();
        }
    }

    /**
     * The generated key, revoked, refused at start as a configured one is.
     *
     * <p>It was refused at its first use instead: the instance started, and every signature and every
     * route that needed the key answered 500 — a revocation that reads as an outage, discovered by
     * whoever exported first. Only a key that can be read is refused here; one that cannot (no
     * {@code ENCRYPTION_KEY}, or the wrong one) signs nothing either way, and its refusal stays the
     * first use's, with the reason it already gives. Nothing is generated or re-sealed at start.
     */
    private void refuseRevokedStoredKey() {
        String stored = settings.internalValue(STORED_KEY).orElse("").trim();
        if (stored.isEmpty()) {
            return;
        }
        KeyMaterial key;
        try {
            key = KeyMaterial.of(CosignSigner.parsePrivateKey(decrypt(stored)));
        } catch (RuntimeException unreadable) {
            return;
        }
        refuseRevoked(key);
    }

    public PublicKey getPublicKey() {
        return material().publicKey();
    }

    public String getPublicKeyPem() {
        return material().publicKeyPem();
    }

    public String getKeyId() {
        return material().keyId();
    }

    public String sign(byte[] payload) {
        return CosignSigner.sign(payload, material().privateKey());
    }

    public DsseEnvelope wrapAndSignDsse(String payloadType, byte[] payload) {
        KeyMaterial key = material();
        return CosignSigner.wrapAndSignDsse(payloadType, payload, key.privateKey(), key.keyId());
    }

    /**
     * Whether {@code base64Signature} is Vectispire's signature over {@code payload}, by the active key
     * or one it replaced; never by a revoked one.
     */
    public boolean verify(byte[] payload, String base64Signature) {
        return verify(payload, base64Signature, null).valid();
    }

    /**
     * @param keyId the key the signature was checked against — the caller's, when one was supplied;
     *     without one, the published key it matched, and null when it matched none
     * @param vectispireKey whether that key is one of Vectispire's signing keys, active or not; without
     *     a supplied key, true: what was checked is Vectispire's keys
     * @param keyStatus where that key stands, when it is one of Vectispire's; null otherwise, and null
     *     when the signature matched none of them
     */
    public record Verification(boolean valid, String keyId, boolean vectispireKey, KeyStatus keyStatus, String message) {}

    /**
     * The active key first, then the ones it replaced, most recent first.
     *
     * <p><b>The status is the record's, not this instance's.</b> It was decided by comparing each key
     * with the one this instance signs with, so through a rolling restart the instances behind one
     * load balancer published contradictory lists — the old ones calling the new key retired — and
     * which one a consumer read depended on the request. The record is shared: every instance
     * answers the same.
     *
     * <p><b>Readable without the signing key.</b> The list is public halves only, and the revocation
     * list is in it; an instance whose own key cannot be loaded — {@code ENCRYPTION_KEY} lost, say —
     * still publishes what it recorded, where it used to answer 500 on every one of these routes.
     */
    public List<PublishedKey> publishedKeys() {
        // Before the read: loading the key records it, and the list must show what was recorded.
        Optional<KeyMaterial> active = signingIfAvailable();
        List<Known> known = new ArrayList<>(known());
        // The key that signs is always published, whatever the row says: it is written before the
        // first signature, but a restore of an older dump can take it away under a running instance.
        active.filter(key -> known.stream().noneMatch(k -> k.keyId().equals(key.keyId())))
                .ifPresent(key -> known.add(Known.of(key.publicKey(), null, null)));
        return known.stream()
                .map(k -> new PublishedKey(k.keyId(), statusOf(k),
                        CosignSigner.toPem(CosignSigner.parsePublicKey(k.der())), k.activeFrom(), k.retiredAt()))
                .sorted(Comparator.comparing((PublishedKey k) -> k.status() != KeyStatus.ACTIVE)
                        .thenComparing(PublishedKey::retiredAt, Comparator.nullsFirst(Comparator.reverseOrder())))
                .toList();
    }

    /**
     * The PEM {@code public-key.pub} serves: the key the list calls active, so that it agrees with the
     * list on every instance. Only when the record names none — nothing signed yet — is it this
     * instance's key, loaded (or generated) as for a signature.
     */
    public String activePublicKeyPem() {
        return publishedKeys().stream().filter(k -> k.status() == KeyStatus.ACTIVE).findFirst()
                .map(PublishedKey::publicKeyPem).orElseGet(() -> material().publicKeyPem());
    }

    public Optional<PublishedKey> publishedKey(String keyId) {
        return publishedKeys().stream().filter(k -> k.keyId().equalsIgnoreCase(keyId)).findFirst();
    }

    /**
     * Checks a signature, against Vectispire's key or against one the caller supplies.
     *
     * <p><b>The answer names the key it was checked against.</b> It used to check against the
     * caller's key when one was given and still answer "valid and authentic" with <em>Vectispire's</em>
     * key id: anybody could sign a forged document with their own key and obtain a response — or a
     * screenshot — saying Vectispire had signed it. A supplied key is still accepted, to let a
     * reviewer check a third party's signature, but the result says whose key it is.
     */
    public Verification verify(byte[] payload, String base64Signature, String suppliedPublicKey) {
        if (suppliedPublicKey == null || suppliedPublicKey.isBlank()) {
            // **Every published key, the active one first.** A document signed before a rotation was
            // reported as not matching "Vectispire's signing key", which an auditor reads as forged.
            // Each key answers with the status the list gives it — never "active" because it happens
            // to be the key of the instance that took the request.
            for (PublishedKey key : publishedKeys()) {
                if (CosignSigner.verify(payload, base64Signature, CosignSigner.parsePublicKey(key.publicKeyPem()))) {
                    return answer(true, key.keyId(), key.status(), key.retiredAt());
                }
            }
            // No key named and no status: it answered with the active key's id and "ACTIVE", which a
            // reader of the response alone takes for the key that signed — and an active one at that.
            return new Verification(false, null, true, null,
                    "Signature does not match any of Vectispire's signing keys for this payload.");
        }
        PublicKey supplied = CosignSigner.parsePublicKey(suppliedPublicKey);
        String suppliedId = CosignSigner.computeKeyId(supplied);
        boolean valid = CosignSigner.verify(payload, base64Signature, supplied);
        Optional<PublishedKey> known = publishedKey(suppliedId);
        if (!valid) {
            return new Verification(false, suppliedId, known.isPresent(), known.map(PublishedKey::status).orElse(null),
                    "Signature does not match the supplied key for this payload.");
        }
        if (known.isEmpty()) {
            return new Verification(true, suppliedId, false, null,
                    "Signature valid for the key you supplied, which is not Vectispire's signing key nor one it signed "
                            + "with before: this does not show that Vectispire signed the document.");
        }
        return answer(true, suppliedId, known.get().status(), known.get().retiredAt());
    }

    /** A signature that matches one of Vectispire's keys, said for the key's status. */
    private static Verification answer(boolean matches, String keyId, KeyStatus status, Instant retiredAt) {
        return switch (status) {
            case ACTIVE -> new Verification(matches, keyId, true, status, "Signature valid: signed with Vectispire's signing key.");
            // No claim on when the document was signed: through a rolling restart an instance not yet
            // restarted signs with the key after the record has retired it. Retired is not revoked —
            // what the key signed, whenever, is Vectispire's.
            case RETIRED -> new Verification(matches, keyId, true, status,
                    "Signature valid: signed with a previous Vectispire signing key, replaced on " + retiredAt
                            + ". The key was retired, not revoked: what it signed remains authentic.");
            // Not valid, though the arithmetic matches: whoever holds a revoked key can sign anything
            // with it, so a match proves nothing about Vectispire.
            case REVOKED -> new Verification(false, keyId, true, status,
                    "The signature matches a Vectispire signing key that has been revoked: do not trust this document.");
        };
    }

    private KeyMaterial material() {
        KeyMaterial current = material;
        if (current != null && registered) {
            return current;
        }
        synchronized (this) {
            if (material == null) {
                material = refuseRevoked(loadOrCreate());
            }
            if (!registered) {
                register(material);
                registered = true;
            }
            return material;
        }
    }

    private KeyMaterial refuseRevoked(KeyMaterial key) {
        if (revokedKeyIds.contains(key.keyId())) {
            throw new IllegalStateException("The document signing key " + key.keyId() + " is listed in "
                    + "vectispire.signing.revoked-keys and cannot sign. Configure a new key in vectispire.signing.key.");
        }
        return key;
    }

    private KeyStatus statusOf(Known key) {
        if (revokedKeyIds.contains(key.keyId())) {
            return KeyStatus.REVOKED;
        }
        return key.retiredAt() == null ? KeyStatus.ACTIVE : KeyStatus.RETIRED;
    }

    /**
     * This instance's key, when it can be loaded. A key that cannot be is still refused to every
     * signature, with its reason; the published list goes on without it, and says why once.
     */
    private Optional<KeyMaterial> signingIfAvailable() {
        try {
            return Optional.of(material());
        } catch (RuntimeException unavailable) {
            if (!warnedUnavailable) {
                warnedUnavailable = true;
                log.warn("The document signing key cannot be loaded ({}); the published keys are served from the record "
                        + "alone.", unavailable.getMessage());
            }
            return Optional.empty();
        }
    }

    private List<Known> known() {
        return read(settings.internalValue(KNOWN_KEYS)).keys();
    }

    /** The record as read: the lines taken, and the ones refused, kept verbatim. */
    private record Read(List<Known> keys, List<String> refused) {}

    /**
     * The record, a line refused when it does not hold together.
     *
     * <p><b>A line refused, not the record.</b> Refusing the whole row would take every published key
     * down with the one line — and with it the revocation list, which is what a consumer needs to read
     * during an incident. A refused line publishes nothing and verifies nothing, which errs the safe
     * way: a document signed with that key stops verifying, nothing starts to. The line stays in the
     * row (a rotation writes it back verbatim) so that whoever investigates finds what was written,
     * and the warning says once per line and instance that it is there.
     */
    private Read read(Optional<String> row) {
        List<Known> keys = new ArrayList<>();
        List<String> refused = new ArrayList<>();
        row.map(String::trim).filter(r -> !r.isEmpty()).ifPresent(r -> r.lines().filter(l -> !l.isBlank()).forEach(line -> {
            Optional<Known> known = Known.parse(line);
            if (known.isPresent()) {
                keys.add(known.get());
            } else {
                refused.add(line);
                if (warnedLines.add(line)) {
                    String claimed = line.split(";", 2)[0];
                    log.warn("A line of {} is refused: its key cannot be read, or {} is not the key's own id. "
                            + "It is neither published nor used to verify.", KNOWN_KEYS,
                            claimed.substring(0, Math.min(claimed.length(), 64)));
                }
            }
        }));
        return new Read(List.copyOf(keys), List.copyOf(refused));
    }

    /**
     * Records the key this instance signs with as the active one, before it signs anything.
     *
     * <p>The key it replaces is marked retired, not removed: a document signed before the rotation is
     * verified against it. With a configured key in front of a stored one — the first rotation of an
     * installation that let Vectispire generate its key — the stored key's public half is recorded too,
     * since it is the one every document so far was signed with and nothing else would ever say so.
     *
     * <p>Conditional on what was read, so two instances starting together each re-read and agree. Two
     * instances on two different keys — a rolling restart through a rotation — do not take the record
     * from each other: the restarted one records its key as active, and one started before that keeps
     * signing with the key the record now calls retired, whose signatures verify as a previous key's
     * until it restarts. Each used to record its own in turn, the last to sign first winning — the old
     * key, published active after the restart was over.
     */
    private void register(KeyMaterial active) {
        for (int attempt = 0; attempt < 5; attempt++) {
            Optional<String> read = settings.internalValue(KNOWN_KEYS);
            Read record = read(read);
            List<Known> before = record.keys();
            List<Known> after = reconcile(before, active);
            if (after.equals(before)) {
                return;
            }
            String value = Stream.concat(after.stream().map(Known::line), record.refused().stream())
                    .collect(Collectors.joining("\n"));
            boolean written = read.isEmpty()
                    ? settings.storeInternalIfAbsent(KNOWN_KEYS, value)
                    // In a transaction of its own, like the re-seal: the first signature may be made
                    // inside a read-only transaction.
                    : settings.resealInternal(KNOWN_KEYS, read.get(), value);
            if (written) {
                Known retired = before.stream().filter(k -> k.retiredAt() == null && !k.keyId().equals(active.keyId()))
                        .findFirst().orElse(null);
                if (retired != null) {
                    log.info("The document signing key is now {}; {} is retired and stays published for verification.",
                            active.keyId(), retired.keyId());
                }
                return;
            }
        }
        throw new IllegalStateException("Could not record the document signing key " + active.keyId()
                + " among the published keys: the row kept changing under five attempts.");
    }

    private List<Known> reconcile(List<Known> before, KeyMaterial active) {
        Instant now = clock.instant();
        List<Known> after = new ArrayList<>();
        boolean present = false;
        for (Known k : before) {
            if (k.keyId().equals(active.keyId())) {
                present = true;
                if (k.retiredAt() != null && k.retiredAt().isAfter(startedAt)) {
                    // **Retired under this instance, not before it**: a rolling restart, and this is an
                    // instance not yet restarted signing for the first time. Taking the record back
                    // would publish the old key as active once the restart is over, and nothing would
                    // put the new one back before its own next start. It signs, as a retired key. The two
                    // instants come from two hosts' clocks: a rollback started within their skew of the
                    // rotation it undoes is read as this case, and takes one more restart.
                    log.warn("The document signing key {} was replaced on {}, after this instance started; it signs "
                            + "with it until it restarts, and the record keeps it retired.", k.keyId(), k.retiredAt());
                    return before;
                }
                // A key brought back — a rotation rolled back — is active again from now.
                after.add(k.retiredAt() == null ? k : new Known(k.keyId(), now, null, k.der()));
            } else {
                after.add(k.retiredAt() == null ? new Known(k.keyId(), k.activeFrom(), now, k.der()) : k);
            }
        }
        if (!present) {
            after.add(Known.of(active.publicKey(), now, null));
        }
        if (!configuredKey.isEmpty()) {
            storedPublicKey().filter(stored -> after.stream().noneMatch(k -> k.keyId().equals(CosignSigner.computeKeyId(stored))))
                    .ifPresent(stored -> after.add(Known.of(stored, null, now)));
        }
        return after;
    }

    /**
     * The public half of the generated key a configured key replaced, when there is one and it can be
     * read. Unreadable is not fatal here: the configured key signs either way, and the warning says
     * what will not verify.
     */
    private Optional<PublicKey> storedPublicKey() {
        String stored = settings.internalValue(STORED_KEY).orElse("").trim();
        if (stored.isEmpty()) {
            return Optional.empty();
        }
        try {
            return Optional.of(CosignSigner.derivePublicKey(CosignSigner.parsePrivateKey(decrypt(stored))));
        } catch (RuntimeException unreadable) {
            log.warn("The stored document signing key cannot be read ({}): documents it signed will not be verifiable "
                    + "against the published keys.", unreadable.getMessage());
            return Optional.empty();
        }
    }

    private KeyMaterial loadOrCreate() {
        String stored = settings.internalValue(STORED_KEY).orElse("").trim();
        if (!stored.isEmpty()) {
            return KeyMaterial.of(CosignSigner.parsePrivateKey(decryptResealing(stored)));
        }

        KeyPair generated = CosignSigner.generateKeyPair();
        // Throws MissingEncryptionKeyException without ENCRYPTION_KEY: a key that cannot be kept is
        // a key whose signatures die with this process.
        boolean inserted = settings.storeInternalIfAbsent(
                STORED_KEY, encryption.encrypt(CosignSigner.toPem(generated.getPrivate()), CONTEXT));

        // **Read back, and use what is stored.** Two instances starting together can each generate
        // a key; the first insert wins, the second is refused and never overwrites it, and both
        // sign with the row that won. A multi-instance deployment can still set
        // vectispire.signing.key and avoid the question.
        String kept = settings.internalValue(STORED_KEY).orElseThrow().trim();
        KeyMaterial key = KeyMaterial.of(CosignSigner.parsePrivateKey(decrypt(kept)));
        if (inserted) {
            log.info("Generated the document signing key {} and stored it encrypted. Keep ENCRYPTION_KEY: without it, "
                    + "this key cannot be read back and nothing can be signed.", key.keyId());
        } else {
            log.info("Another instance stored the document signing key {} first; signing with it.", key.keyId());
        }
        return key;
    }

    /**
     * The key, re-sealed under the current {@code ENCRYPTION_KEY} when a previous one opened it.
     *
     * <p>It is written once and read once per start, so nothing else would ever move it: after a
     * rotation it stayed under the old key, and removing that key — as the procedure said once the
     * SSH keys were done — stopped every signature. A failed re-seal is not a failed load: the key
     * is still the right one, and the next start tries again.
     */
    private String decryptResealing(String stored) {
        SecretCipher.Decrypted secret = encryption.inspect(stored, CONTEXT);
        String plain = decrypt(stored);
        if (secret.state() == SecretCipher.SecretState.PREVIOUS_KEY) {
            try {
                if (settings.resealInternal(STORED_KEY, stored, encryption.encrypt(plain, CONTEXT))) {
                    log.info("Re-sealed the document signing key under the current ENCRYPTION_KEY.");
                }
            } catch (RuntimeException refused) {
                log.warn("The document signing key is still sealed under a previous ENCRYPTION_KEY and could not be "
                        + "re-sealed now ({}); the next start tries again.", refused.getMessage());
            }
        }
        return plain;
    }

    @Override
    public List<StoreCensus> census() {
        String stored = settings.internalValue(STORED_KEY).orElse("");
        return List.of(new StoreCensus.Counter("Document signing key", "re-sealed by the next start")
                .add(encryption.sealOf(stored, CONTEXT))
                .done());
    }

    private String decrypt(String stored) {
        SecretCipher.Decrypted secret = encryption.inspect(stored, CONTEXT);
        if (secret.state() == SecretCipher.SecretState.UNREADABLE) {
            throw new IllegalStateException("The stored document signing key cannot be decrypted by any configured "
                    + "ENCRYPTION_KEY. It is not replaced: a new key would make every document already signed "
                    + "unverifiable. Restore the key it was encrypted with, or set vectispire.signing.key.");
        }
        return secret.plainText();
    }
}
