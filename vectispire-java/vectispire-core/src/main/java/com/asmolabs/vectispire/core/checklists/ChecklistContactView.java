package com.asmolabs.vectispire.core.checklists;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * One profile of a project's checklist — a value of its template's contact column — and the account it
 * is linked to (decision 0044).
 *
 * @param profile the profile's key, upper-cased as the route names it: {@code PO}, {@code ARCH}
 * @param label the column's own spelling, as a screen shows it: {@code Arch}
 * @param openLines the lines of this profile still to fill in — unanswered, or carried and waiting for
 *     confirmation — in the project's draft; 0 when the newest revision is not a draft
 * @param accountId the account linked; null while none is
 * @param accountName its name as the candidates name it ({@link ChecklistContactCandidate#name}); null while
 *     none is linked, for an account that no longer exists, and when neither name may be printed
 * @param warning why the account linked would not be reminded: {@code account_gone}, {@code
 *     account_inactive}, {@code no_email} or {@code cannot_fill}; null when it would, and while none is
 *     linked
 */
public record ChecklistContactView(
        String profile,
        String label,
        int openLines,
        @Schema(types = {"integer", "null"}, format = "int64", description = "The account linked; null while none is.")
                Long accountId,
        @Schema(types = {"string", "null"}, description = "The linked account's name, as the candidates name it; null "
                + "while none is linked, for an account gone, and when neither name may be printed.")
                String accountName,
        @Schema(types = {"string", "null"}, allowableValues = {"account_gone", "account_inactive", "no_email", "cannot_fill"},
                description = "Why the linked account would not be reminded; null when it would, and while none is linked.")
                String warning) {}
