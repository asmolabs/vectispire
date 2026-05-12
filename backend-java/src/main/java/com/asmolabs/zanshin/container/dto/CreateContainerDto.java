package com.asmolabs.zanshin.container.dto;

import jakarta.validation.constraints.NotBlank;

public record CreateContainerDto(
    String registry,
    @NotBlank(message = "Image name is required")
    String imageName,
    String tag,
    Integer scanIntervalMinutes,
    String scanCron
) {}
