package com.asmolabs.vectispire.core.persistence;

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
 * A token for cloning over HTTPS, bound to the host it was issued for (decision 0022).
 *
 * <p><b>{@code token} holds a ciphertext, never a token</b>, encrypted with the row as context —
 * see {@code SecretCipher.gitTokenContext} — so a ciphertext copied into another row does not
 * decrypt. The identifier is assigned before the row exists for that reason, as for
 * {@link SshKeyEntity}, and {@link #isNew} says so to Spring Data.
 */
@Entity
@Table(name = "t_git_token")
public class GitTokenEntity implements Persistable<UUID> {

    @Transient
    private boolean persisted;

    @Id
    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "id", nullable = false)
    private UUID id;

    @Column(name = "name", length = 255, nullable = false)
    private String name;

    /** The only host this token is ever presented to. Lower case, no port, no scheme. */
    @Column(name = "host", length = 255, nullable = false)
    private String host;

    /** Some forges want a user name with the token, most accept any; absent sends a fixed one. */
    @Column(name = "username", length = 255)
    private String username;

    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "token", nullable = false)
    private String token;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

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

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
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

    @PostLoad
    @PostPersist
    void markPersisted() {
        this.persisted = true;
    }
}
