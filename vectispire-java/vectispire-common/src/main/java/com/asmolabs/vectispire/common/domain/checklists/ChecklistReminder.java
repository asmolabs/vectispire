package com.asmolabs.vectispire.common.domain.checklists;

import java.time.LocalDate;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * The weekly reminder of the checklist lines still to fill in (decision 0044): to the account a project
 * linked to a profile, the lines of that profile; to the CISOs, the profiles nobody can be reminded for.
 *
 * <p><b>A pure function of what the service read</b>, like {@code PostureDigest}: which lines, which
 * accounts and which projects are the service's questions; what the message says is answered here,
 * without a database.
 *
 * <p><b>Plain text, in English</b>, as every message Vectispire sends by e-mail: there is no template
 * engine and no server-side translation, and a reminder is not the message to introduce one with.
 */
public final class ChecklistReminder {

    /** The lines named per project and profile; the rest are counted, and the page lists them all. */
    static final int LINES_NAMED = 20;

    /** A control is a sentence of the template's, and a mail line is not a page: cut, and marked as cut. */
    static final int CONTROL_SHOWN = 160;

    private ChecklistReminder() {}

    /** A line to fill in: its place in the checklist, and what it asks. */
    public record Line(int position, String control) {

        public Line {
            Objects.requireNonNull(control, "control");
        }
    }

    /** One profile's lines on one project, for the account linked to it there. */
    public record ProfileLines(long projectId, String projectName, String profile, List<Line> lines) {

        public ProfileLines {
            Objects.requireNonNull(projectName, "projectName");
            Objects.requireNonNull(profile, "profile");
            lines = List.copyOf(lines);
        }
    }

    /** Why a profile with lines to fill in reminds nobody — said to the CISO in these words. */
    public enum Gap {
        NOBODY_LINKED("no account is linked to it"),
        ACCOUNT_GONE("the account linked to it no longer exists"),
        ACCOUNT_INACTIVE("the account linked to it is deactivated"),
        NO_EMAIL("the account linked to it has no e-mail address"),
        CANNOT_FILL("the account linked to it can no longer fill in this project's checklist");

        private final String words;

        Gap(String words) {
            this.words = words;
        }

        public String words() {
            return words;
        }

        /** The token a screen receives, lower-case like the other wire values. */
        public String wireName() {
            return name().toLowerCase(java.util.Locale.ROOT);
        }
    }

    /** A profile with lines to fill in on a project, and why nobody is reminded of them. */
    public record Unreached(long projectId, String projectName, String profile, int lines, Gap gap) {

        public Unreached {
            Objects.requireNonNull(projectName, "projectName");
            Objects.requireNonNull(profile, "profile");
            Objects.requireNonNull(gap, "gap");
        }
    }

    /** A message: its subject and its body. */
    public record Message(String subject, String body) {}

    /**
     * To the account linked to the profiles: every line of theirs still to fill in, by project.
     *
     * @param name how the account is addressed; empty when it has no name a message may print
     * @param publicUrl the deployment's address, for a link to each project's checklist; empty when unset
     */
    public static Message toContact(Optional<String> name, List<ProfileLines> profiles, LocalDate weekStarting,
            Optional<String> publicUrl) {
        int total = profiles.stream().mapToInt(profile -> profile.lines().size()).sum();
        StringBuilder body = new StringBuilder();
        body.append(name.map(person -> "Hello " + person + ",").orElse("Hello,")).append("\n\n");
        body.append(total == 1 ? "One checklist line" : total + " checklist lines")
                .append(" for which you are the contact ").append(total == 1 ? "is" : "are")
                .append(" not filled in yet: unanswered, or carried from an earlier version and waiting for "
                        + "confirmation.\n");
        for (ProfileLines profile : profiles) {
            body.append("\nProject \"").append(profile.projectName()).append("\", profile ").append(profile.profile())
                    .append(" — ").append(count(profile.lines().size())).append('\n');
            profile.lines().stream().limit(LINES_NAMED).forEach(line -> body.append("  Line ").append(line.position())
                    .append(": ").append(shown(line.control())).append('\n'));
            if (profile.lines().size() > LINES_NAMED) {
                body.append("  … and ").append(count(profile.lines().size() - LINES_NAMED)).append(" more\n");
            }
            link(publicUrl, profile.projectId()).ifPresent(url -> body.append("  ").append(url).append('\n'));
        }
        body.append("\nYou receive this once a week, for the week of ").append(weekStarting)
                .append(", while lines of a profile a project linked to your account wait to be filled in. "
                        + "Whoever edits the project's checklist can link the profile to somebody else.\n");
        return new Message("[Vectispire] " + (total == 1 ? "1 checklist line waits" : total + " checklist lines wait")
                + " for you", body.toString());
    }

    /**
     * To a CISO: the profiles whose lines remind nobody, by project, each with its reason.
     *
     * @param publicUrl the deployment's address, for a link to each project's checklist; empty when unset
     */
    public static Message toCiso(List<Unreached> unreached, LocalDate weekStarting, Optional<String> publicUrl) {
        StringBuilder body = new StringBuilder();
        body.append("Hello,\n\n")
                .append(unreached.size() == 1 ? "One profile has" : unreached.size() + " profiles have")
                .append(" checklist lines to fill in that nobody is reminded of:\n\n");
        for (Unreached profile : unreached) {
            body.append("Project \"").append(profile.projectName()).append("\", profile ").append(profile.profile())
                    .append(" — ").append(count(profile.lines())).append(": ").append(profile.gap().words()).append('\n');
            link(publicUrl, profile.projectId()).ifPresent(url -> body.append("  ").append(url).append('\n'));
        }
        body.append("\nLink each profile to an account that can fill in the project's checklist, on the checklist's "
                        + "page, under Contacts. You receive this once a week, for the week of ")
                .append(weekStarting).append(", as a CISO, while a profile with lines to fill in reminds nobody.\n");
        return new Message("[Vectispire] " + (unreached.size() == 1 ? "1 checklist profile" : unreached.size()
                + " checklist profiles") + " without a contact", body.toString());
    }

    private static String count(int lines) {
        return lines == 1 ? "1 line" : lines + " lines";
    }

    /** One line of text: a control may hold line breaks, and a long one is cut where the reader sees it is. */
    private static String shown(String control) {
        String single = ChecklistText.normalize(control);
        return single.length() <= CONTROL_SHOWN ? single : single.substring(0, CONTROL_SHOWN - 1).strip() + "…";
    }

    private static Optional<String> link(Optional<String> publicUrl, long projectId) {
        return publicUrl.map(url -> url.replaceAll("/+$", "") + "/projects/" + projectId + "/checklist");
    }
}
