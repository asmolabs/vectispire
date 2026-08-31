# Lire les résultats

Le premier scan d'un dépôt réel renvoie plus que ce que quiconque corrigera. C'est normal, et
le parcourir par ordre de gravité est la façon dont un backlog cesse d'être trié du tout. Cette
page parle de l'ordre qui, lui, fonctionne.

## Constats, issues, état, triage

Quatre mots, et les confondre est la principale source de malentendu.

**Constat** — une observation issue d'un scan. Éphémère par nature.

**Issue** — le même problème suivi d'un scan à l'autre : première apparition, nombre
d'occurrences, existence d'un correctif, décision prise. L'empreinte qui l'identifie ignore
délibérément la version du paquet, si bien qu'une dépendance qui reste vulnérable sur trois
correctifs successifs garde un historique et une décision.

**État** — `open` ou `resolved`. Écrit **uniquement par le pipeline**, à partir de ce que les
scanners ont observé à la dernière exécution.

**Statut de triage** — le vocabulaire VEX : *affecté*, *non affecté*, *corrigé*, *en cours
d'examen*. Écrit **uniquement par une personne**.

Tenir l'état et le triage à part est délibéré. Si supprimer un constat le marquait résolu,
« résolu » cesserait de vouloir dire quoi que ce soit, et personne ne pourrait distinguer un
problème corrigé d'un problème que quelqu'un a décidé de ne pas regarder.

## Classer par exploitabilité, pas par gravité

Un score CVSS dit à quel point une vulnérabilité serait grave si elle était exploitée. Il ne
dit rien sur le fait que quelqu'un l'exploite. Deux enrichissements répondent à cela, et tous
deux sont attachés à chaque vulnérabilité :

- **EPSS** — la probabilité que cette CVE soit exploitée dans la nature dans les 30 prochains
  jours.
- **CISA KEV** — si elle est *activement exploitée*, comme un fait constaté plutôt que comme
  une prédiction.

Une entrée KEV avec un CVSS moyen passe devant une critique que personne n'a jamais exploitée.
La liste des issues se filtre sur les deux.

## Puis par ce que vous pouvez réellement corriger aujourd'hui

Chaque issue enregistre si votre projet a **déclaré** le paquet lui-même ou si quelque chose
d'autre l'a entraîné — directe contre transitive, lu depuis le graphe de dépendances du SBOM.

La distinction est opérationnelle, pas académique. Une CVE critique dans une dépendance
déclarée, c'est un changement de version cet après-midi. La même CVE quatre niveaux plus bas
attend une publication en amont que vous ne contrôlez pas. Classées à égalité, elles produisent
un backlog que personne ne termine : restreignez donc la liste à ce qui est corrigeable
aujourd'hui, et traitez cela d'abord.

Quand le SBOM ne porte pas de graphe de dépendances, la réponse est **inconnue** — une réponse
absente plutôt qu'une réponse par défaut.

Le filtre **Corrigeables seulement** va plus loin : il masque tout ce dont aucune version
correctrice n'est publiée.

## Ce qu'un scan a changé

Chaque scan rapporte son delta : quelles issues sont nouvelles, lesquelles sont résolues. C'est
la vue qui vaut la lecture sur un scan récurrent, parce que le total courant bouge à peine d'une
semaine à l'autre alors que le delta est là où se trouve la nouvelle.

Pour la tendance plutôt que l'instantané, la série « backlog dans le temps » du tableau de bord
montre le backlog courant jour par jour, ce qui est apparu face à ce qui a été résolu, et le
délai moyen de résolution. Ce dernier chiffre est affiché **absent** plutôt que zéro quand rien
n'a été résolu, parce qu'un zéro se lit comme « corrigé le jour de son apparition ».

## Deux états avec un backlog vide {#two-states-with-an-empty-backlog}

Un backlog vide passe toutes les politiques — y compris quand il est vide parce que rien n'a
jamais tourné. La vue d'ensemble Sécurité nomme les deux cas qu'aucun autre écran ne nommait :

- une cible **jamais analysée** ;
- une cible dont le **dernier scan a échoué**.

Les deux paraissent vertes partout ailleurs. Vérifiez-les avant de conclure quoi que ce soit
d'un tableau de bord propre.

## Suite

[Trier les issues →](../guide/issues.md) · [Faire échouer une construction là-dessus →](../integrations/ci-gate.md)
