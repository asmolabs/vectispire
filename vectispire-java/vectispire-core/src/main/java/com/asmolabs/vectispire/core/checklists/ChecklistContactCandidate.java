package com.asmolabs.vectispire.core.checklists;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * An account a project's checklist profile may be linked to: active, of a role that writes, and seeing
 * the whole project (decision 0044). Its id and its name — never its address, nor a name that is one.
 *
 * @param name the display name, or the user name when that is not an e-mail address; null when neither
 *     may be printed, and a screen names the account by its id
 */
public record ChecklistContactCandidate(
        long accountId,
        @Schema(types = {"string", "null"}, description = "The display name, or the user name when that is not an "
                + "e-mail address; null when neither may be printed.")
                String name) {}
