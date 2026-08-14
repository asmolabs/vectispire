import { DEFAULT_WARN_DAYS } from '../eol/matching';
import {
    DEFAULT_MIN_SEVERITY,
    SETTING_ALLOW_PRIVATE_URL,
    SETTING_MIN_SEVERITY,
    SETTING_NOTIFY_ON_KEV,
    SETTING_WEBHOOK_URL
} from '../notifications/payload';
import { DEFAULT_KEEP_PER_TARGET, DEFAULT_MAX_AGE_DAYS, SETTING_RETENTION_KEEP_PER_TARGET, SETTING_RETENTION_MAX_AGE_DAYS } from '../retention/policy';
import {
    SETTING_ENRICHMENT_ENABLED,
    SETTING_EOL_ENABLED,
    SETTING_EOL_WARN_DAYS,
    SETTING_LICENSE_BLOCKLIST,
    SETTING_SAST_ENABLED,
    SETTING_TICKET_ALLOW_PRIVATE_URL,
    SETTING_TICKET_BASE_URL,
    SETTING_TICKET_ISSUE_TYPE,
    SETTING_TICKET_LABELS,
    SETTING_TICKET_PROJECT,
    SETTING_TICKET_PROVIDER,
    SETTING_TICKET_USER
} from './keys';
import { DEFAULT_JIRA_ISSUE_TYPE, DEFAULT_LABELS, PROVIDER_NONE } from '../tickets/ticket';
import { DEFAULT_AI_REVIEW_MODEL, DEFAULT_OLLAMA_URL, SETTING_AI_REVIEW_ALLOW_REMOTE, SETTING_AI_REVIEW_ENABLED, SETTING_AI_REVIEW_MODEL, SETTING_AI_REVIEW_OLLAMA_URL } from '../ai-review/prompt';

/**
 * Les réglages que l'application expose, et **seulement ceux qu'un service lit vraiment**.
 *
 * C'est la règle qui gouverne ce fichier : un formulaire qui accepte une valeur et n'en
 * fait rien est pire qu'un formulaire qui ne l'offre pas. L'opérateur croit avoir
 * configuré quelque chose, et le comportement ne change pas — il conclut que l'outil est
 * cassé, ou pire, ne le remarque jamais.
 *
 * Un réglage n'entre donc dans ce catalogue **qu'une fois son lecteur porté**. Les clés
 * des services encore absents — tickets, revue par modèle, licences — n'y sont pas, et
 * c'est délibéré, pas un oubli.
 *
 * Le catalogue porte aussi le type et le libellé, pour que l'écran se rende
 * génériquement : ajouter un réglage ne doit pas demander de toucher à l'interface.
 */

export type SettingType = 'boolean' | 'integer' | 'text' | 'severity';

export interface SettingDefinition {
    key: string;
    type: SettingType;
    /**
     * Sa **valeur** est un secret, même si sa clé ne l'est pas.
     *
     * Une URL de webhook Slack, Teams ou Discord n'est pas une configuration : c'est une
     * capacité au porteur. Qui la connaît peut publier dans le canal — celui-là même où
     * l'équipe attend les alertes de Zanshin, donc celui où un message forgé porte le
     * plus. La lire ne demande aucun droit d'écriture, ce qui la rendait accessible à
     * n'importe quel compte.
     *
     * L'écran reçoit alors `configured` sans la valeur, comme pour le jeton de tickets.
     */
    sensitive?: boolean;
    /** Le groupe sous lequel l'écran range le réglage. */
    section: string;
    label: string;
    /** Ce que change ce réglage, et surtout ce qu'il ne change pas. */
    help: string;
    default: string;
}

export const SETTINGS_CATALOG: SettingDefinition[] = [
    {
        key: SETTING_ENRICHMENT_ENABLED,
        type: 'boolean',
        section: 'Enrichissement',
        label: 'Interroger EPSS et le catalogue KEV',
        help:
            "Seuls des identifiants de CVE quittent la machine — jamais de code ni de SBOM. Désactivé, le compteur " +
            "« activement exploitées » restera à zéro, ce qui veut alors dire « on n'a pas demandé » et non « il n'y en a pas ».",
        default: 'true'
    },
    {
        key: SETTING_EOL_ENABLED,
        type: 'boolean',
        section: 'Fin de vie',
        label: 'Détecter les plateformes en fin de support',
        help:
            "Une classe de risque sans CVE : un environnement échu ne recevra pas de correctif pour la prochaine " +
            "vulnérabilité, quelle qu'elle soit. Désactiver laisse les constats existants **ouverts** plutôt que de les " +
            "résoudre — « on a cessé de regarder » n'est pas « c'est réglé ».",
        default: 'true'
    },
    {
        key: SETTING_EOL_WARN_DAYS,
        type: 'integer',
        section: 'Fin de vie',
        label: "Fenêtre d'avertissement (jours)",
        help:
            "Un cycle dont la fin tombe dans cette fenêtre est signalé en sévérité moyenne. Au-delà, rien : tout a une fin " +
            "de vie un jour, et signaler une version supportée encore trois ans apprendrait à filtrer ce type.",
        default: String(DEFAULT_WARN_DAYS)
    },
    {
        key: SETTING_SAST_ENABLED,
        type: 'boolean',
        section: 'Analyse du code source',
        label: 'Analyser le code avec Semgrep',
        help:
            "Désactivé par défaut, et c'est une décision d'exploitation : le premier scan d'un dépôt ordinaire fait passer " +
            "son backlog de quelques dizaines de vulnérabilités à quelques milliers de constats. Les constats de qualité " +
            "ne font jamais échouer une compilation et ne déclenchent jamais de notification. Désactiver laisse les " +
            "constats existants ouverts plutôt que de les résoudre.",
        default: 'false'
    },
    {
        key: SETTING_RETENTION_KEEP_PER_TARGET,
        type: 'integer',
        section: 'Rétention',
        label: 'Charges brutes gardées par cible',
        help:
            "Les SBOM et sorties de scanner des N derniers scans de chaque cible sont conservés quel que soit leur âge. " +
            "Zéro veut dire « aucune limite sur cet axe ». Les constats, les problèmes et les résumés ne sont jamais purgés.",
        default: String(DEFAULT_KEEP_PER_TARGET)
    },
    {
        key: SETTING_RETENTION_MAX_AGE_DAYS,
        type: 'integer',
        section: 'Rétention',
        label: 'Âge maximal des charges brutes (jours)',
        help:
            "Les deux règles se conjuguent : une charge n'est purgée que si elle est **à la fois** hors de la fenêtre " +
            "ci-dessus et plus vieille que cet âge. Les deux à zéro désactivent la purge.",
        default: String(DEFAULT_MAX_AGE_DAYS)
    },
    {
        key: SETTING_WEBHOOK_URL,
        type: 'text',
        sensitive: true,
        section: 'Notifications',
        label: 'URL du webhook',
        help:
            "Un POST JSON générique, qui atteint Slack, Teams, Discord, Mattermost ou un script. Vide désactive les " +
            "notifications. L'URL est validée à chaque envoi : une destination privée est refusée sauf réglage explicite.",
        default: ''
    },
    {
        key: SETTING_MIN_SEVERITY,
        type: 'severity',
        section: 'Notifications',
        label: 'Sévérité minimale notifiée',
        help: "Rien de nouveau au-dessus de ce seuil, aucun message. Une notification par scan apprend à filtrer le canal.",
        default: DEFAULT_MIN_SEVERITY
    },
    {
        key: SETTING_NOTIFY_ON_KEV,
        type: 'boolean',
        section: 'Notifications',
        label: 'Notifier toute vulnérabilité activement exploitée',
        help: "Quelle que soit sa sévérité : le seuil seul écarterait un « moyen » exploité aujourd'hui.",
        default: 'true'
    },
    {
        key: SETTING_ALLOW_PRIVATE_URL,
        type: 'boolean',
        section: 'Notifications',
        label: 'Autoriser une URL de webhook privée',
        help:
            "Pour un bus interne. Désactivé par défaut : une URL de webhook qui résout vers une adresse privée est bien " +
            "plus souvent une tentative de falsification de requête côté serveur qu'un point de terminaison d'intranet. " +
            "Le point d'accès de métadonnées d'instance reste refusé dans tous les cas.",
        default: 'false'
    },
    {
        key: SETTING_LICENSE_BLOCKLIST,
        type: 'text',
        section: 'Licences',
        label: 'Licences interdites',
        help:
            "Identifiants SPDX séparés par des virgules, par exemple « GPL-3.0-only,AGPL-3.0-only ». Vide, rien n'est " +
            "signalé : quelles licences sont interdites est une décision d'organisation, pas une décision technique. " +
            "Lu du SBOM déjà produit — aucun outil supplémentaire n'est nécessaire.",
        default: ''
    },
    {
        key: SETTING_TICKET_PROVIDER,
        type: 'text',
        section: 'Gestionnaire de tickets',
        label: 'Fournisseur',
        help:
            "« gitlab », « jira », ou « none » pour désactiver. Un ticket est ouvert pour tout problème qui ferait " +
            "échouer une compilation selon la politique de gate — il n'y a pas de second seuil, pour qu'un seul endroit " +
            "définisse « assez sérieux pour agir ».",
        default: PROVIDER_NONE
    },
    {
        key: SETTING_TICKET_BASE_URL,
        type: 'text',
        // Pas un secret au sens du webhook, mais une carte du réseau interne qu'un compte
        // sans droits n'a aucune raison de lire.
        sensitive: true,
        section: 'Gestionnaire de tickets',
        label: 'URL du gestionnaire',
        help:
            "Une destination interne est acceptée ici, contrairement au webhook : un GitLab ou un Jira auto-hébergé vit " +
            "couramment sur un réseau interne. Le point d'accès de métadonnées d'instance reste refusé.",
        default: ''
    },
    {
        key: SETTING_TICKET_PROJECT,
        type: 'text',
        section: 'Gestionnaire de tickets',
        label: 'Projet',
        help: "Le chemin GitLab (« groupe/projet ») ou la clé de projet Jira (« SEC »).",
        default: ''
    },
    {
        key: SETTING_TICKET_USER,
        type: 'text',
        section: 'Gestionnaire de tickets',
        label: 'Compte Jira',
        help: "L'adresse du compte, exigée par Jira à côté du jeton pour l'authentification de base. GitLab ne s'en sert pas.",
        default: ''
    },
    {
        key: SETTING_TICKET_ISSUE_TYPE,
        type: 'text',
        section: 'Gestionnaire de tickets',
        label: 'Type de ticket Jira',
        help: "Le nom du type dans le projet visé. GitLab ne s'en sert pas.",
        default: DEFAULT_JIRA_ISSUE_TYPE
    },
    {
        key: SETTING_TICKET_LABELS,
        type: 'text',
        section: 'Gestionnaire de tickets',
        label: 'Étiquettes',
        help: 'Séparées par des virgules, posées sur chaque ticket ouvert.',
        default: DEFAULT_LABELS
    },
    {
        key: SETTING_TICKET_ALLOW_PRIVATE_URL,
        type: 'boolean',
        section: 'Gestionnaire de tickets',
        label: 'Autoriser une URL interne',
        help: "Activé par défaut. Décochez-le pour un déploiement qui n'utilise qu'un gestionnaire hébergé.",
        default: 'true'
    },
    {
        key: SETTING_AI_REVIEW_ENABLED,
        type: 'boolean',
        section: 'Revue par modèle',
        label: 'Relire le code avec un modèle local',
        help:
            "Un complément léger aux scanners, pas un moteur SAST : une seule invite, sans reproductibilité garantie. " +
            "Ses constats sont étiquetés comme venant d'un modèle et exclus du gate par défaut — c'est l'atténuation " +
            "structurelle contre l'injection d'invite, le code analysé étant une entrée contrôlée par un tiers.",
        default: 'false'
    },
    {
        key: SETTING_AI_REVIEW_OLLAMA_URL,
        type: 'text',
        sensitive: true,
        section: 'Revue par modèle',
        label: 'URL du service Ollama',
        help:
            "**Ce point de terminaison reçoit le code source du dépôt scanné.** Le risque n'est donc pas qu'il pointe " +
            "vers l'interne, mais vers l'externe : une URL publique bien formée est exactement ce à quoi ressemble un " +
            "canal d'exfiltration. Une destination publique est refusée sauf aveu explicite ci-dessous.",
        default: DEFAULT_OLLAMA_URL
    },
    {
        key: SETTING_AI_REVIEW_MODEL,
        type: 'text',
        section: 'Revue par modèle',
        label: 'Modèle',
        help: "Le nom tel qu'Ollama le connaît. Il n'a pas besoin d'être déjà installé pour être enregistré ici.",
        default: DEFAULT_AI_REVIEW_MODEL
    },
    {
        key: SETTING_AI_REVIEW_ALLOW_REMOTE,
        type: 'boolean',
        section: 'Revue par modèle',
        label: 'Autoriser un Ollama distant',
        help:
            "Désactivé par défaut, et c'est le réglage le plus lourd de conséquences de cet écran : l'activer permet " +
            "d'envoyer le code source vers un hôte public.",
        default: 'false'
    }
];

/** Les défauts du catalogue, pour que l'écran sache ce qu'une clé absente vaut. */
export function catalogDefaults(): Record<string, string> {
    return Object.fromEntries(SETTINGS_CATALOG.map((definition) => [definition.key, definition.default]));
}

/** La définition d'une clé, ou `undefined` si elle n'est pas exposée. */
export function definitionFor(key: string): SettingDefinition | undefined {
    return SETTINGS_CATALOG.find((definition) => definition.key === key);
}

/**
 * Une valeur acceptable pour ce réglage, ou un message disant pourquoi elle ne l'est pas.
 *
 * Validée au point de saisie plutôt qu'à la lecture : un entier illisible se lirait
 * silencieusement comme son défaut, et l'opérateur n'apprendrait jamais que sa valeur a
 * été ignorée.
 */
export function validate(definition: SettingDefinition, value: string): string | null {
    switch (definition.type) {
        case 'boolean':
            return value === 'true' || value === 'false' ? null : 'Valeur attendue : « true » ou « false ».';
        case 'integer': {
            const parsed = Number(value);
            return value.trim() !== '' && Number.isInteger(parsed) && parsed >= 0 ? null : 'Valeur attendue : un entier positif ou nul.';
        }
        case 'severity':
            return ['critical', 'high', 'medium', 'low'].includes(value)
                ? null
                : 'Valeur attendue : critical, high, medium ou low.';
        default:
            return null;
    }
}
