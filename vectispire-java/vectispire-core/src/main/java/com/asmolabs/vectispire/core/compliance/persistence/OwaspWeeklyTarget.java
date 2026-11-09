package com.asmolabs.vectispire.core.compliance.persistence;

/** A target the weekly OWASP record names, by kind and identifier — what the orphan sweep checks. */
public record OwaspWeeklyTarget(String kind, long id) {}
