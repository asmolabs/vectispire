package com.asmolabs.vectispire.core.access.persistence;

/**
 * One membership with its account's username, read in the statement that reads the membership.
 *
 * @param username null when no account holds the id any more
 */
public record TeamMembership(Long teamId, Long userId, String username) {}
