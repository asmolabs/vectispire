package com.asmolabs.zanshin.settings.dto;

public record UpdateEmailSettingsDto(
    String smtpHost,
    String smtpPort,
    String smtpUser,
    String smtpPass,
    String smtpFrom
) {}
