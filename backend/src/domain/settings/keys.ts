/**
 * The setting keys whose reader lives in the service layer.
 *
 * Declared here rather than next to their service because the catalog needs them, and the
 * domain cannot import a service without inverting the layers. A key is data, not
 * behaviour: its natural place is at the lowest level.
 */

export const SETTING_ENRICHMENT_ENABLED = 'enrichment_enabled';
export const SETTING_EOL_ENABLED = 'eol_detection_enabled';
export const SETTING_EOL_WARN_DAYS = 'eol_warn_days';

/**
 * Source-code analysis by Semgrep.
 *
 * Off by default: the first scan of an ordinary repository takes its backlog from a few
 * dozen vulnerabilities to a few thousand findings, and that is an operational decision, not
 * a default to switch on unknowingly.
 *
 * **Read by the control plane, not by the worker**: a remote agent has no database and
 * cannot read it itself — so it travels on the task.
 */
export const SETTING_SAST_ENABLED = 'sast_enabled';

/**
 * The ticket tracker.
 *
 * **The token is encrypted at rest**, unlike the other settings: it grants write access to
 * the tracker, which is a different class of secret from a URL. It is therefore not exposed
 * by the catalog — a secret is not re-read in a form.
 *
 * **Private is allowed by default here**, unlike the webhook: a self-hosted GitLab or Jira
 * commonly lives on an internal network.
 */
export const SETTING_TICKET_PROVIDER = 'ticket_provider';
export const SETTING_TICKET_BASE_URL = 'ticket_base_url';
export const SETTING_TICKET_PROJECT = 'ticket_project';
export const SETTING_TICKET_TOKEN = 'ticket_token';
export const SETTING_TICKET_USER = 'ticket_user';
export const SETTING_TICKET_ISSUE_TYPE = 'ticket_issue_type';
export const SETTING_TICKET_LABELS = 'ticket_labels';
export const SETTING_TICKET_ALLOW_PRIVATE_URL = 'ticket_allow_private_url';

/**
 * The forbidden licenses, as comma-separated SPDX identifiers.
 *
 * **Empty by default, and nothing is reported while it is**: which licenses are forbidden
 * is an organizational decision, not a technical one. A default would impose a legal
 * judgement in the operator's place.
 */
export const SETTING_LICENSE_BLOCKLIST = 'license_blocklist';
