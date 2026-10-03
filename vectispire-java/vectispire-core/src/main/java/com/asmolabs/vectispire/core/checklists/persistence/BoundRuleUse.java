package com.asmolabs.vectispire.core.checklists.persistence;

/** A rule bound to a line of the version a project's checklist answers — what the change-review demand reads. */
public record BoundRuleUse(Long projectId, String boundRule) {}
