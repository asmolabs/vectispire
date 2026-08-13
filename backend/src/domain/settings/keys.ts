/**
 * Les clés de réglage dont le lecteur vit dans la couche service.
 *
 * Déclarées ici plutôt qu'à côté de leur service parce que le catalogue en a besoin, et
 * que le domaine ne peut pas importer un service sans inverser les couches. Une clé est
 * une donnée, pas un comportement : sa place naturelle est au niveau le plus bas.
 */

export const SETTING_ENRICHMENT_ENABLED = 'enrichment_enabled';
export const SETTING_EOL_ENABLED = 'eol_detection_enabled';
export const SETTING_EOL_WARN_DAYS = 'eol_warn_days';

/**
 * L'analyse du code source par Semgrep.
 *
 * Désactivée par défaut : le premier scan d'un dépôt ordinaire fait passer son backlog de
 * quelques dizaines de vulnérabilités à quelques milliers de constats, et c'est une
 * décision d'exploitation, pas un défaut à activer sans le savoir.
 *
 * **Lue par le plan de contrôle, pas par le travailleur** : un agent distant n'a pas de
 * base et ne peut pas la lire lui-même — elle voyage donc sur la tâche.
 */
export const SETTING_SAST_ENABLED = 'sast_enabled';

/**
 * Le gestionnaire de tickets.
 *
 * **Le jeton est chiffré au repos**, contrairement aux autres réglages : il donne un accès
 * en écriture au gestionnaire, ce qui est une autre classe de secret qu'une URL. Il n'est
 * donc pas exposé par le catalogue — un secret ne se relit pas dans un formulaire.
 *
 * **Le privé est autorisé par défaut ici**, à l'inverse du webhook : un GitLab ou un Jira
 * auto-hébergé vit couramment sur un réseau interne.
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
 * Les licences interdites, en identifiants SPDX séparés par des virgules.
 *
 * **Vide par défaut, et rien n'est signalé tant qu'elle l'est** : quelles licences sont
 * interdites est une décision d'organisation, pas une décision technique. Un défaut
 * imposerait un jugement juridique à la place de l'opérateur.
 */
export const SETTING_LICENSE_BLOCKLIST = 'license_blocklist';
