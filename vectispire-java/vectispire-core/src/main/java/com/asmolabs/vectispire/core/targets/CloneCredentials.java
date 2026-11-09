package com.asmolabs.vectispire.core.targets;

import com.asmolabs.vectispire.core.targets.persistence.GitTokenRepository;
import com.asmolabs.vectispire.core.targets.persistence.SshKeyRepository;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * A repository's clone credentials as the scan dispatcher needs them: <b>still encrypted</b>.
 *
 * <p><b>Why the ciphertext, and not the secret.</b> The dispatcher is where a deployment key is
 * decrypted, and only there — and only when it is to be delivered: for an agent in {@code local}
 * mode it is neither read nor decrypted. That decision is an authorization, and it stays whole in one
 * place. The dispatcher read these rows through the repositories while they were layered; the rows
 * are {@code targets}' (decision 0029), and this hands over what the row holds, with the identifier
 * the ciphertext is bound to.
 */
@Service
@Transactional(readOnly = true)
public class CloneCredentials {

    /** An HTTPS token as stored: the ciphertext is bound to {@code id}, and names the host it is for. */
    public record StoredGitToken(UUID id, String name, String host, String username, String ciphertext) {}

    /** An SSH private key as stored: the ciphertext is bound to {@code id}. */
    public record StoredSshKey(UUID id, String name, String ciphertext) {}

    private final GitTokenRepository gitTokens;
    private final SshKeyRepository sshKeys;

    public CloneCredentials(GitTokenRepository gitTokens, SshKeyRepository sshKeys) {
        this.gitTokens = gitTokens;
        this.sshKeys = sshKeys;
    }

    /** Empty when the token has been deleted since the repository named it. */
    public Optional<StoredGitToken> gitToken(UUID id) {
        return gitTokens.findById(id)
                .map(token -> new StoredGitToken(
                        token.getId(), token.getName(), token.getHost(), token.getUsername(), token.getToken()));
    }

    /** Empty when the key has been deleted since the repository named it. */
    public Optional<StoredSshKey> sshKey(UUID id) {
        return sshKeys.findById(id).map(key -> new StoredSshKey(key.getId(), key.getName(), key.getPrivateKey()));
    }
}
