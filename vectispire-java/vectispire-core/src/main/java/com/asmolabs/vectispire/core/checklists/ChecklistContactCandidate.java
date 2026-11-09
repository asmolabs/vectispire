package com.asmolabs.vectispire.core.checklists;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * An account a project's checklist profile may be linked to: active, of a role that writes, and seeing
 * the whole project (decision 0044). Its id and its display name — never its user name, its address, nor a
 * name that is one.
 *
 * @param name the display name under {@code AccountNames}' rule; null when the account has none, or one that
 *     is an e-mail address, and a screen names the account by its id
 */
public record ChecklistContactCandidate(
        long accountId,
        @Schema(types = {"string", "null"}, description = "The display name; null when the account has none, or one "
                + "that is an e-mail address.")
                String name) {}
