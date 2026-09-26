# Réglages

L'essentiel de la configuration d'exécution vit **dans la base de données** et s'édite ici une
fois l'application lancée — enrichissement, fin de support, rétention, notifications, licences,
tracker, revue par modèle.

Un réglage n'apparaît sur cette page qu'à partir du moment où un service le lit réellement.
Cette règle empêche l'écran de devenir un musée d'options qui ne font rien.

Seul ce qui est nécessaire pour atteindre cet écran est une variable d'environnement. Voir
[Configuration](../reference/configuration.md).

## Qui peut changer quoi

Un CISO écrit l'essentiel de cette page, mais **pas la destination d'un identifiant**. Le jeton du
tracker et la clé OpenAI ne sont réglés que par un administrateur ; les réglages qui décident où
ils partent — l'URL du tracker, *Autoriser une URL de tracker privée*, l'URL OpenAI et
l'acceptation qui laisse partir le code vers un point d'accès distant — sont donc aussi ceux d'un
administrateur, et s'affichent en lecture seule pour les autres. Sans cela, un rôle qui ne peut pas
lire un identifiant pourrait le recueillir en le dirigeant vers son propre hôte.

Le formulaire SIEM fonctionne à l'inverse, parce que le même rôle y règle le point d'arrivée et
l'en-tête : changer le point d'arrivée **efface l'en-tête enregistré**, sauf si un nouveau est saisi
avec lui. Un en-tête est émis pour un collecteur. Il n'est envoyé qu'avec le webhook, et refusé avec
un protocole syslog — voir l'[export SIEM](../integrations/siem.md) pour les protocoles, le point
d'arrivée que chacun lit et les événements envoyés.

## Longueur d'une valeur

Un réglage texte contient jusqu'à 16 000 caractères, et un identifiant — le jeton du tracker, les
secrets de webhook, la clé OpenAI — jusqu'à 8 192. Au-delà, le formulaire refuse avec un message.
Les vrais jetons sont bien plus courts : avant cette limite, un identifiant de plus de 160 caractères
environ ne pouvait pas être enregistré du tout.

## Enrichissement

Consultations EPSS et CISA KEV. Ce sont les seuls appels sortants du pipeline en dehors du
catalogue de fin de support, et ils transportent des identifiants CVE et rien d'autre.

Les désactiver est une option pour un déploiement isolé du réseau. Cela vous coûte la capacité
de classer par exploitabilité, qui est le classement qui fonctionne — voir
[Lire les résultats](../getting-started/reading-results.md).

## Fin de support

Le catalogue endoflife.date, qui transporte des noms de produits et des versions. La couverture
est délibérément limitée aux produits — langages, exécutions, cadriciels, distributions —
plutôt qu'à chaque bibliothèque.

## Licences

La liste de blocage évaluée contre les données du SBOM. Ce qui doit y figurer est la décision
de votre organisation : l'AGPL est fatale pour un produit propriétaire distribué et sans objet
pour un service interne jamais livré.

## Rétention

Combien de temps les scans et leurs artefacts bruts sont conservés. Voir
[Rotation et purge](maintenance.md).

## Notifications

Destinations webhook, Teams et courriel, leurs secrets, et le rapport de posture hebdomadaire.
Couvert sous [Notifications](../integrations/notifications.md).

## Tracker

GitLab ou Jira : URL, projet, jeton. Couvert sous [Tickets](../integrations/ticketing.md).

## Revue de code par IA

Désactivée par défaut. Un LLM local exécuté via [Ollama](https://ollama.com) relit le code
source avec une invite d'« architecte sécurité », en complément léger de Grype, gitleaks et
checkov — et non en remplacement d'aucun d'eux. Une fois activée, elle s'exécute sur les scans
de dépôt, et son résultat narratif ainsi que ses constats normalisés apparaissent dans le
détail du scan.

Posez l'URL d'Ollama (par défaut `http://localhost:11434`) et choisissez un modèle. La liste
est lue en direct depuis le `/api/tags` d'Ollama, si bien que ce que vous avez réellement
téléchargé s'y trouve. Si Ollama est injoignable, la liste déroulante retombe sur deux
suggestions plutôt que d'être vide — ce qui est aussi le symptôme à reconnaître.

Il n'y a délibérément aucun réglage pour dire *où* Ollama tourne. En natif ou en conteneur,
Vectispire lui parle en HTTP simple dans les deux cas, et le choix concerne l'accès au GPU sur
votre hôte plutôt que quoi que ce soit que Vectispire fasse.

```bash
ollama pull gemma4:12b-it-qat   # ~7,2 Go, ~9–10 Go de RAM/VRAM — recommandé
ollama pull gemma4:e4b-it-qat   # ~6,1 Go, plus léger et plus rapide, revue de moindre qualité
```

!!! note "Apple Silicon"
    Docker Desktop n'a ni passage GPU ni Metal sur Apple Silicon : un Ollama en conteneur y
    tourne uniquement sur processeur et l'inférence est nettement plus lente. Installez-le en
    natif sur ces machines.

## Personnalisation

`VECTISPIRE_BRAND_NAME` pose le nom d'instance affiché dans l'en-tête, dans les rapports PDF et
dans les exports SARIF, VEX et CSAF.
