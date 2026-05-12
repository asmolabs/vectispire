package com.asmolabs.zanshin.repository.services;

import com.asmolabs.zanshin.common.services.EncryptionService;
import com.asmolabs.zanshin.repository.entities.SSHKey;
import com.asmolabs.zanshin.repository.repositories.SSHKeyRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class SSHKeyService {

    private final SSHKeyRepository sshKeyRepository;
    private final EncryptionService encryptionService;

    public String getDecryptedKey(UUID id) {
        SSHKey key = sshKeyRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("SSH Key not found"));
        return encryptionService.decrypt(key.getPrivateKey());
    }
}
