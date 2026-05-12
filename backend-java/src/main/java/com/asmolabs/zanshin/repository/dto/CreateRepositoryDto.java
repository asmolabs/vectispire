package com.asmolabs.zanshin.repository.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record CreateRepositoryDto(
    @NotBlank(message = "Please provide a valid Git URL")
    @Pattern(regexp = "^(https?://|git@|ssh://)([^\\s]+)$", message = "Please provide a valid Git URL (HTTPS or SSH)")
    String url,

    String name,

    @NotBlank(message = "Branch is required")
    String branch,

    String subPath,

    String sshKeyId,

    Integer scanIntervalMinutes,

    String scanCron
) {}
