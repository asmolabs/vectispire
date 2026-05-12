package com.asmolabs.zanshin.repository.services;

import com.asmolabs.zanshin.repository.entities.AuditLog;
import com.asmolabs.zanshin.repository.repositories.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AuditLogService {

    private final AuditLogRepository auditLogRepository;

    public List<AuditLog> findAll() {
        return auditLogRepository.findAllByOrderByTimestampDesc();
    }

    public AuditLog logAction(String userId, String resourceId, String operationType, String description) {
        AuditLog log = AuditLog.builder()
                .userId(userId)
                .resourceId(resourceId)
                .operationType(operationType)
                .description(description)
                .build();
        return auditLogRepository.save(log);
    }
}
