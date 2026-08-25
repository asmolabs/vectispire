# 0003 — Les agents parlent en long-polling HTTP, jamais à la base

**Date :** 2026-08-06 · **Statut :** accepté

## Contexte

Exécuter des analyses sur des nœuds distants exigeait un transport qui n'étende pas la confiance
du control plane à la machine qui lance le scanner. Un agent distant se trouve par définition sur
le réseau de quelqu'un d'autre : c'est le composant le plus susceptible d'être compromis, et le
moins susceptible qu'on s'en aperçoive.

## Décision

Les agents interrogent `GET /api/v1/agents/jobs?wait=30` en HTTP sortant. Rien n'écoute côté agent
— `web-application-type: none`, il n'ouvre donc aucun port — et les redirections sont refusées :
l'adresse du control plane est une configuration, et une redirection enverrait une réclamation, une
clé d'API ou un résultat d'analyse vers un hôte que personne n'a déclaré.

## Ce que l'agent détient, précisément

La version courte — « l'agent ne détient aucun identifiant » — est fausse, et un évaluateur qui le
découvre seul a raison de dévaluer tout ce qui l'entoure. La frontière exacte a trois parties :

**Aucune base.** Imposé par le graphe de modules et non par convention : `vectispire-agent` ne
dépend pas de `vectispire-core`, donc aucun pilote JDBC, aucun Hibernate et aucun Spring Data n'est
sur son classpath de compilation. Atteindre la base n'échoue pas en relecture, cela échoue à la
compilation. `AgentIsolationTest` le réaffirme et vérifie d'abord que l'import de classes n'est pas
vide, de sorte qu'un package renommé ne puisse pas vider la règle en silence.

**Aucune `ENCRYPTION_KEY`.** Rien dans le module agent ne la lit. C'est la propriété qui justifie
l'existence de l'agent : cette clé déchiffre *toutes* les clés de déploiement et tous les jetons
d'intégration que la plateforme détient, et un agent la détenant transformerait un worker compromis
en la perte de l'ensemble.

**Des clés de déploiement, mais scellées à lui seul, et dans un seul mode.** Un agent déclaré
[`CredentialsMode.LOCAL`](../../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/domain/agents/CredentialsMode.java)
— le défaut et la recommandation — utilise son propre accès git et ne reçoit rien. Un agent déclaré
`DELEGATED` reçoit la clé privée d'un dépôt avec chaque tâche, dans une
[`SealedEnvelope`](../../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/domain/crypto/SealedEnvelope.java) :
X25519 vers la clé publique que l'agent a annoncée à l'enrôlement, HKDF, puis AES-256-GCM. Le
control plane ne peut pas sceller pour un agent qui n'en a jamais annoncé, et chaque envoi est
audité — c'est la condition à laquelle ce mode existe.

L'agent refuse une enveloppe qu'il ne peut pas ouvrir plutôt que de passer le chiffré à git. Cela
compte plus qu'il n'y paraît : une chaîne scellée remise à git est une clé qui échoue, et l'échec se
lit comme un problème de permissions ou de dépôt, ailleurs, bien plus tard.

**Un mode inconnu est lu comme `LOCAL`.** Jamais comme `DELEGATED` : la lecture sûre de « je ne sais
pas ce que cet agent a le droit de recevoir » est « pas la clé ».

## Conséquences

Le mode est la *seule* chose qui décide si une clé part. Le dispatcher NestJS que ceci remplace
consultait le transport à la place : un agent placé sur une machine moins protégée, sur la promesse
écrite qu'aucune clé ne lui parviendrait, recevait la clé de déploiement déchiffrée de chaque dépôt
dont il réclamait l'analyse — et rien ne routait la file, il pouvait donc toutes les moissonner.
C'est le défaut autour duquel cette décision est façonnée, et la raison pour laquelle le contrôle
porte sur le mode plutôt que sur quoi que ce soit d'observable de la connexion.
