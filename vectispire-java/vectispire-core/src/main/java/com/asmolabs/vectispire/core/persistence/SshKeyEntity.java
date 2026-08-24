package com.asmolabs.vectispire.core.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import org.springframework.data.domain.Persistable;
import jakarta.persistence.Transient;
import jakarta.persistence.PostPersist;
import jakarta.persistence.PostLoad;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import java.time.Instant;
import java.util.UUID;

/**
 * A deployment key.
 *
 * <p><b>{@code privateKey} holds a ciphertext, never a key.</b> It is encrypted with the
 * associated data naming this row, so a ciphertext copied into another row does not decrypt —
 * see {@code SecretCipher.privateKeyContext}. The column is text because the sealed form is
 * base64 and grows with the key.
 */
@Entity
@Table(name = "t_ssh_key")
public class SshKeyEntity implements Persistable<UUID> {


    /**
     * Assigned, not generated, and therefore {@link Persistable}.
     *
     * <p>The identifier has to exist <em>before</em> the row does: it is the encryption context the private key is sealed under, so the ciphertext cannot be built without it.
     *
     * <p>Spring Data decides insert-versus-update from "is the id null", so an assigned id makes
     * every save a merge — which on a row that does not exist yet fails rather than inserting.
     * {@code isNew} answers the question honestly instead.
     */
    @Transient
    private boolean persisted;

    @Id
    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "id", nullable = false)
    private UUID id;

    @Column(name = "name", length = 255, nullable = false)
    private String name;

    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "private_key", nullable = false)
    private String privateKey;

    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "public_key")
    private String publicKey;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    @Override
    public boolean isNew() {
        return !persisted;
    }

    /** Both callbacks, so a row read back is never mistaken for one that has yet to be written. */
    @PostLoad
    @PostPersist
    void markPersisted() {
        this.persisted = true;
    }
}
