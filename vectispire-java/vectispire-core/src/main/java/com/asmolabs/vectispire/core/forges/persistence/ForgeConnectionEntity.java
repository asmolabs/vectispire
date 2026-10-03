package com.asmolabs.vectispire.core.forges.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.PostLoad;
import jakarta.persistence.PostPersist;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import java.time.Instant;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import org.springframework.data.domain.Persistable;

/**
 * A read-only credential to a forge, from which repositories are discovered (decision 0037 §2).
 *
 * <p><b>{@code token} holds a ciphertext, never a token</b>, encrypted with the row as context — see
 * {@code SecretCipher.forgeConnectionContext} — so a ciphertext copied into another row does not decrypt.
 * The identifier is assigned before the row exists for that reason, as for the clone tokens, and
 * {@link #isNew} says so to Spring Data. No getter of this entity reaches a route: the service answers a
 * view without the token.
 */
@Entity
@Table(name = "t_forge_connection")
public class ForgeConnectionEntity implements Persistable<UUID> {

    @Transient
    private boolean persisted;

    @Id
    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "id", nullable = false)
    private UUID id;


    @Column(name = "name", length = 255, nullable = false)
    private String name;

    /** {@code ForgeKind}'s wire name. */
    @Column(name = "kind", length = 20, nullable = false)
    private String kind;

    /** {@code ForgeEdition}'s wire name, derived from the address when it was typed. */
    @Column(name = "edition", length = 40, nullable = false)
    private String edition;

    /** The web address; the API's root is derived from it, never stored apart from it. */
    @Column(name = "base_url", length = 512, nullable = false)
    private String baseUrl;

    /** GitHub's organisation or user the token was issued for; null for GitLab. */
    @Column(name = "owner", length = 100)
    private String owner;

    /** The administrator's statement that the server is internal: {@code INTERNAL_ALLOWED} instead of {@code PUBLIC_ONLY}. */
    @Column(name = "internal_network", nullable = false)
    private boolean internalNetwork;

    /** The CA bundle pinned for this server, in place of the runtime's trust store; null for that store. */
    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "ca_pem")
    private String caPem;

    /** <b>A ciphertext, never a token</b>, with the row as context. */
    @Column(name = "token", length = 2048, nullable = false)
    private String token;

    /** {@code ForgeCredential.Kind}'s wire name, as the last probe identified it. */
    @Column(name = "credential_kind", length = 40, nullable = false)
    private String credentialKind;

    /** Comma-separated, as the forge reported them; null when it reports none. */
    @Column(name = "scopes", length = 1000)
    private String scopes;

    /** Null when the forge does not say — unknown is not {@code false}. */
    @Column(name = "can_write")
    private Boolean canWrite;

    @Column(name = "token_expires_at")
    private Instant tokenExpiresAt;

    @Column(name = "forge_version", length = 64)
    private String forgeVersion;

    @Column(name = "probed_at", nullable = false)
    private Instant probedAt;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "created_by", length = 255, nullable = false)
    private String createdBy;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Column(name = "updated_by", length = 255, nullable = false)
    private String updatedBy;

    @Override
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

    public String getKind() {
        return kind;
    }

    public void setKind(String kind) {
        this.kind = kind;
    }

    public String getEdition() {
        return edition;
    }

    public void setEdition(String edition) {
        this.edition = edition;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public String getOwner() {
        return owner;
    }

    public void setOwner(String owner) {
        this.owner = owner;
    }

    public boolean isInternalNetwork() {
        return internalNetwork;
    }

    public void setInternalNetwork(boolean internalNetwork) {
        this.internalNetwork = internalNetwork;
    }

    public String getCaPem() {
        return caPem;
    }

    public void setCaPem(String caPem) {
        this.caPem = caPem;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getCredentialKind() {
        return credentialKind;
    }

    public void setCredentialKind(String credentialKind) {
        this.credentialKind = credentialKind;
    }

    public String getScopes() {
        return scopes;
    }

    public void setScopes(String scopes) {
        this.scopes = scopes;
    }

    public Boolean getCanWrite() {
        return canWrite;
    }

    public void setCanWrite(Boolean canWrite) {
        this.canWrite = canWrite;
    }

    public Instant getTokenExpiresAt() {
        return tokenExpiresAt;
    }

    public void setTokenExpiresAt(Instant tokenExpiresAt) {
        this.tokenExpiresAt = tokenExpiresAt;
    }

    public String getForgeVersion() {
        return forgeVersion;
    }

    public void setForgeVersion(String forgeVersion) {
        this.forgeVersion = forgeVersion;
    }

    public Instant getProbedAt() {
        return probedAt;
    }

    public void setProbedAt(Instant probedAt) {
        this.probedAt = probedAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public String getCreatedBy() {
        return createdBy;
    }

    public void setCreatedBy(String createdBy) {
        this.createdBy = createdBy;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Instant updatedAt) {
        this.updatedAt = updatedAt;
    }

    public String getUpdatedBy() {
        return updatedBy;
    }

    public void setUpdatedBy(String updatedBy) {
        this.updatedBy = updatedBy;
    }

    @Override
    public boolean isNew() {
        return !persisted;
    }

    @PostLoad
    @PostPersist
    void markPersisted() {
        this.persisted = true;
    }
}
