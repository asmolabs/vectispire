package com.asmolabs.zanshin.common.domain.settings;

import com.asmolabs.zanshin.common.domain.aireview.AiReview;
import com.asmolabs.zanshin.common.domain.eol.LifeCycle;
import com.asmolabs.zanshin.common.domain.issues.RemediationSla;
import com.asmolabs.zanshin.common.domain.issues.Severity;
import com.asmolabs.zanshin.common.domain.notifications.NotificationSelection;
import com.asmolabs.zanshin.common.domain.retention.RetentionPolicy;
import com.asmolabs.zanshin.common.domain.tickets.TicketProvider;
import com.asmolabs.zanshin.common.domain.tickets.Tickets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * The settings the application exposes, and <b>only those a service actually reads</b>.
 *
 * <p>That is the rule governing this file. A form that accepts a value and does nothing with
 * it is worse than a form that does not offer it: the operator believes they have configured
 * something, the behaviour does not change, and they conclude the tool is broken — or worse,
 * never notice.
 *
 * <p><b>The rule is checked when the reading service is wired, not here.</b> During the port
 * nothing reads anything yet, so applying it literally would leave the catalog empty. Every
 * key below has its rule ported into {@code zanshin-common}; what remains is to confirm, as
 * each service lands, that it genuinely consults the key it claims to.
 *
 * <p>An enum rather than a list of records, for the same reason as {@code PolicyFlag}: the
 * definition travels with the key, so "this setting is not exposed" stops being an absent
 * lookup a caller has to remember to handle.
 */
public enum Setting {

    ENRICHMENT_ENABLED("enrichment_enabled", SettingType.BOOLEAN, Section.ENRICHMENT,
            "Query EPSS and the KEV catalog",
            "Only CVE identifiers leave the machine — never code, never a SBOM. Switched off, the "
                    + "\"actively exploited\" counter stays at zero, which then means \"we did not ask\" and not "
                    + "\"there are none\".",
            "true"),

    EOL_ENABLED("eol_detection_enabled", SettingType.BOOLEAN, Section.END_OF_LIFE,
            "Detect platforms past their support window",
            "A class of risk with no CVE attached: an expired environment will receive no fix for the next "
                    + "vulnerability, whatever it turns out to be. Switching this off leaves existing findings "
                    + "**open** rather than resolving them — \"we stopped looking\" is not \"it is fixed\".",
            "true"),

    EOL_WARN_DAYS("eol_warn_days", SettingType.INTEGER, Section.END_OF_LIFE,
            "Warning window (days)",
            "A cycle whose end falls inside this window is reported at medium severity. Beyond it, nothing: "
                    + "everything reaches end of life one day, and flagging a version supported for another three "
                    + "years would teach people to filter this type out.",
            String.valueOf(LifeCycle.DEFAULT_WARNING_WINDOW.toDays())),

    SAST_ENABLED("sast_enabled", SettingType.BOOLEAN, Section.SOURCE_CODE,
            "Analyze the code with Semgrep",
            "Off by default, and that is an operational decision: the first scan of an ordinary repository takes "
                    + "its backlog from a few dozen vulnerabilities to a few thousand findings. Quality findings "
                    + "never fail a build and never trigger a notification. Switching this off leaves existing "
                    + "findings open rather than resolving them.",
            "false"),

    RETENTION_KEEP_PER_TARGET("retention_keep_per_target", SettingType.INTEGER, Section.RETENTION,
            "Raw payloads kept per target",
            "The SBOMs and scanner output of each target's last N scans are kept whatever their age. Zero means "
                    + "\"no limit on this axis\". Findings, issues and summaries are never purged.",
            String.valueOf(RetentionPolicy.DEFAULT.keepPerTarget())),

    RETENTION_MAX_AGE_DAYS("retention_max_age_days", SettingType.INTEGER, Section.RETENTION,
            "Maximum age of raw payloads (days)",
            "The two rules combine: a payload is purged only if it is **both** outside the window above and "
                    + "older than this age. Both at zero disables purging.",
            String.valueOf(RetentionPolicy.DEFAULT.maxAge().toDays())),

    WEBHOOK_URL("notification_webhook_url", SettingType.TEXT, Section.NOTIFICATIONS,
            "Webhook URL",
            "A generic JSON POST, which reaches Slack, Teams, Discord, Mattermost or a script. Empty disables "
                    + "notifications. The URL is validated on every send: a private destination is refused unless "
                    + "explicitly allowed.",
            "", Sensitivity.SECRET),

    TEAMS_WEBHOOK_URL("notification_teams_url", SettingType.TEXT, Section.NOTIFICATIONS,
            "Microsoft Teams webhook URL",
            "The URL of a Teams **workflow** — \"when a Teams webhook request is received\" in Power Automate. "
                    + "The old Office 365 connector was retired, and a workflow is what replaces it. Zanshin posts "
                    + "an Adaptive Card, so nothing has to be mapped in the designer. Empty disables it; it can run "
                    + "beside the generic webhook and the e-mail rather than instead of them.",
            "", Sensitivity.SECRET),

    MAIL_RECIPIENTS("notification_mail_to", SettingType.TEXT, Section.NOTIFICATIONS,
            "E-mail recipients",
            "Comma-separated. Empty disables e-mail. The server itself is configured with `ZANSHIN_MAIL_HOST` and "
                    + "its companions: a mail relay is deployment infrastructure, not something to retype on a "
                    + "settings screen, and its password has no business in a table this application can export.",
            ""),

    NOTIFICATION_MIN_SEVERITY("notification_min_severity", SettingType.SEVERITY, Section.NOTIFICATIONS,
            "Minimum severity notified",
            "Nothing new above this threshold, no message. One notification per scan teaches people to filter "
                    + "the channel.",
            NotificationSelection.DEFAULT_MIN_SEVERITY.wireName()),

    NOTIFY_ON_KEV("notification_always_on_kev", SettingType.BOOLEAN, Section.NOTIFICATIONS,
            "Notify any actively exploited vulnerability",
            "Whatever its severity: the threshold alone would discard a \"medium\" being exploited today.",
            "true"),

    NOTIFICATION_ALLOW_PRIVATE_URL("notification_allow_private_url", SettingType.BOOLEAN, Section.NOTIFICATIONS,
            "Allow a private webhook URL",
            "For an internal bus. Off by default: a webhook URL resolving to a private address is far more often "
                    + "a server-side request forgery attempt than an intranet endpoint. The instance metadata "
                    + "endpoint stays refused in every case.",
            "false"),

    LICENSE_BLOCKLIST("license_blocklist", SettingType.TEXT, Section.LICENSES,
            "Forbidden licenses",
            "Comma-separated SPDX identifiers, for example \"GPL-3.0-only,AGPL-3.0-only\". Empty, nothing is "
                    + "reported: which licenses are forbidden is an organizational decision, not a technical one. "
                    + "Read from the SBOM already produced — no extra tool is needed.",
            ""),

    TARGET_VISIBILITY("target_visibility", SettingType.TEXT, Section.ACCESS,
            "What a non-administrator sees",
            "\"everyone\" means every signed-in account sees every target — the behaviour of a deployment "
                    + "that has never thought about it, and the default so that updating changes nothing. "
                    + "\"assigned\" means an account sees only the targets an administrator has assigned to it, "
                    + "and an account with no assignment sees nothing. Administrators always see everything: "
                    + "somebody has to be able to make the assignments.",
            "everyone"),

    TICKET_PROVIDER("ticket_provider", SettingType.TEXT, Section.TICKETS,
            "Provider",
            "\"gitlab\", \"jira\", or \"none\" to disable. A ticket is opened for any issue that would fail a "
                    + "build under the gate policy — there is no second threshold, so that one single place "
                    + "defines \"serious enough to act on\".",
            TicketProvider.NONE.wireName()),

    TICKET_BASE_URL("ticket_base_url", SettingType.TEXT, Section.TICKETS,
            "Tracker URL",
            "An internal destination is accepted here, unlike the webhook: a self-hosted GitLab or Jira commonly "
                    + "lives on an internal network. The instance metadata endpoint stays refused.",
            // Not a secret in the webhook's sense, but a map of the internal network that an
            // unprivileged account has no reason to read.
            "", Sensitivity.SECRET),

    TICKET_PROJECT("ticket_project", SettingType.TEXT, Section.TICKETS,
            "Project",
            "The GitLab path (\"group/project\") or the Jira project key (\"SEC\").",
            ""),

    TICKET_TOKEN("ticket_token", SettingType.TEXT, Section.TICKETS,
            "Access token",
            "Grants write access to the tracker, which is a different class of secret from a webhook URL: it is "
                    + "therefore encrypted at rest like an SSH key, not stored in the clear alongside the other "
                    + "settings.",
            "", Sensitivity.SECRET),

    TICKET_USER("ticket_user", SettingType.TEXT, Section.TICKETS,
            "Jira account",
            "The account address, required by Jira alongside the token for basic authentication. GitLab does "
                    + "not use it.",
            ""),

    TICKET_ISSUE_TYPE("ticket_issue_type", SettingType.TEXT, Section.TICKETS,
            "Jira issue type",
            "The type name in the target project. GitLab does not use it.",
            Tickets.DEFAULT_JIRA_ISSUE_TYPE),

    TICKET_LABELS("ticket_labels", SettingType.TEXT, Section.TICKETS,
            "Labels",
            "Comma-separated, applied to every ticket opened.",
            String.join(",", Tickets.DEFAULT_LABELS)),

    TICKET_ALLOW_PRIVATE_URL("ticket_allow_private_url", SettingType.BOOLEAN, Section.TICKETS,
            "Allow an internal URL",
            "On by default. Clear it for a deployment that only uses a hosted tracker.",
            "true"),

    AI_REVIEW_ENABLED("ai_review_enabled", SettingType.BOOLEAN, Section.MODEL_REVIEW,
            "Review the code with a local model",
            "A light complement to the scanners, not a SAST engine: a single prompt, with no guaranteed "
                    + "reproducibility. Its findings are tagged as coming from a model and excluded from the gate "
                    + "by default — that is the structural mitigation against prompt injection, the analyzed code "
                    + "being an input controlled by a third party.",
            "false"),

    AI_REVIEW_OLLAMA_URL("ai_review_ollama_url", SettingType.TEXT, Section.MODEL_REVIEW,
            "Ollama service URL",
            "**This endpoint receives the scanned repository's source code.** The risk is therefore not that it "
                    + "points inward, but outward: a well-formed public URL is exactly what an exfiltration "
                    + "channel looks like. A public destination is refused unless explicitly acknowledged below.",
            AiReview.DEFAULT_OLLAMA_URL, Sensitivity.SECRET),

    AI_REVIEW_MODEL("ai_review_model", SettingType.TEXT, Section.MODEL_REVIEW,
            "Model",
            "The name as Ollama knows it. It does not have to be installed already to be saved here.",
            AiReview.DEFAULT_MODEL),

    AI_REVIEW_TIMEOUT_SECONDS("ai_review_timeout_seconds", SettingType.INTEGER, Section.MODEL_REVIEW,
            "How long to wait for the model (seconds)",
            "A local model writing a report takes minutes on ordinary hardware, and the ten seconds that suit a "
                    + "webhook turn every run into \"request timed out\" — which reads as a broken Ollama rather "
                    + "than as a limit set here. The right value depends on the machine and the model, which is "
                    + "why it is a setting and not a constant.",
            String.valueOf(AiReview.DEFAULT_TIMEOUT_SECONDS)),

    AI_REVIEW_ALLOW_REMOTE("ai_review_allow_remote_url", SettingType.BOOLEAN, Section.MODEL_REVIEW,
            "Allow a remote Ollama",
            "Off by default, and it is the most consequential setting on this screen: turning it on allows "
                    + "source code to be sent to a public host.",
            "false"),

    // **The four windows, and the reason each is a setting rather than a constant.** A
    // remediation policy is written by an organisation, not by a tool: the numbers below are the
    // shape most published ones have, and every deployment has its own. What they must not be is
    // absent — an SLA nobody set is an SLA nobody is measured against.
    //
    // Zero disables a severity. The help text says so on every one of them, because the other
    // reading — zero as "due immediately" — turns clearing a field into a backlog entirely in
    // breach, from a gesture that looked like switching something off.
    SLA_CRITICAL_DAYS("sla_critical_days", SettingType.INTEGER, Section.REMEDIATION,
            "Critical: days to remediate",
            "Counted from when the issue was **first seen**, never from the last scan — otherwise a target "
                    + "scanned nightly would reset every deadline every night and nothing would ever be late. "
                    + "Zero disables the deadline for this severity. **No window blocks a gate**: being late is "
                    + "reported to people, not used to stop a deployment that might carry the fix.",
            String.valueOf(RemediationSla.DEFAULT.windowFor(Severity.CRITICAL).orElseThrow().toDays())),

    SLA_HIGH_DAYS("sla_high_days", SettingType.INTEGER, Section.REMEDIATION,
            "High: days to remediate",
            "As above: from the first sighting, zero to disable, and it blocks nothing.",
            String.valueOf(RemediationSla.DEFAULT.windowFor(Severity.HIGH).orElseThrow().toDays())),

    SLA_MEDIUM_DAYS("sla_medium_days", SettingType.INTEGER, Section.REMEDIATION,
            "Medium: days to remediate",
            "As above: from the first sighting, zero to disable, and it blocks nothing.",
            String.valueOf(RemediationSla.DEFAULT.windowFor(Severity.MEDIUM).orElseThrow().toDays())),

    SLA_LOW_DAYS("sla_low_days", SettingType.INTEGER, Section.REMEDIATION,
            "Low: days to remediate",
            "As above. Negligible and unknown severities carry no window at all and are not settable: neither "
                    + "describes work anybody schedules, and a deadline on either would fill the report with "
                    + "lateness that means nothing.",
            String.valueOf(RemediationSla.DEFAULT.windowFor(Severity.LOW).orElseThrow().toDays()));

    /** The group the screen files a setting under. */
    public enum Section {

        ACCESS("Access"),
        ENRICHMENT("Enrichment"),
        END_OF_LIFE("End of life"),
        SOURCE_CODE("Source code analysis"),
        REMEDIATION("Remediation deadlines"),
        RETENTION("Retention"),
        NOTIFICATIONS("Notifications"),
        LICENSES("Licenses"),
        TICKETS("Ticket tracker"),
        MODEL_REVIEW("OWASP review");

        private final String label;

        Section(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }
    }

    /**
     * Whether the <b>value</b> is a secret, even though the key is not.
     *
     * <p>A Slack, Teams or Discord webhook URL is not configuration: it is a bearer capability.
     * Whoever knows it can post in the channel — the very channel where the team awaits
     * Zanshin's alerts, hence the one where a forged message carries most weight. Reading it
     * requires no write permission, which made it reachable by any account.
     *
     * <p>The screen therefore receives "configured" without the value.
     */
    public enum Sensitivity {
        PLAIN,
        SECRET
    }

    private final String key;
    private final SettingType type;
    private final Section section;
    private final String label;
    private final String help;
    private final String defaultValue;
    private final Sensitivity sensitivity;

    Setting(String key, SettingType type, Section section, String label, String help, String defaultValue) {
        this(key, type, section, label, help, defaultValue, Sensitivity.PLAIN);
    }

    Setting(String key, SettingType type, Section section, String label, String help, String defaultValue,
            Sensitivity sensitivity) {
        this.key = key;
        this.type = type;
        this.section = section;
        this.label = label;
        this.help = help;
        this.defaultValue = defaultValue;
        this.sensitivity = sensitivity;
    }

    public String key() {
        return key;
    }

    public SettingType type() {
        return type;
    }

    public Section section() {
        return section;
    }

    public String label() {
        return label;
    }

    /** What this setting changes, and above all what it does not. */
    public String help() {
        return help;
    }

    public String defaultValue() {
        return defaultValue;
    }

    public boolean isSecret() {
        return sensitivity == Sensitivity.SECRET;
    }

    /** Empty when the value is acceptable, otherwise the message to show. */
    public Optional<String> validate(String value) {
        return type.validate(value);
    }

    /** A key's definition, or empty when it is not exposed. */
    public static Optional<Setting> byKey(String key) {
        return Arrays.stream(values()).filter(setting -> setting.key.equals(key)).findFirst();
    }

    /** The defaults, so the screen knows what an absent key is worth. */
    public static Map<String, String> defaults() {
        Map<String, String> defaults = new LinkedHashMap<>();
        for (Setting setting : values()) {
            defaults.put(setting.key, setting.defaultValue);
        }
        return Map.copyOf(defaults);
    }
}
