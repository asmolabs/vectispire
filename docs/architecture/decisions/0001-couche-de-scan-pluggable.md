# 0001 — La couche de scan est pluggable derrière `ScannerEngine`

**Date :** 2026-07-28 · **Statut :** acceptée · **Décideur :** Laurent Boucher

## Contexte

Le pipeline de scan appelait `docker.containers.run` directement, en dur, pour Syft puis
Grype. Ajouter un type d'analyse — secrets, IaC, SAST — ou un mode d'exécution autre que
Docker demandait de dupliquer l'orchestrateur.

Deux conséquences immédiates : le déploiement exigeait le socket Docker sans alternative
possible, et il n'y avait aucun endroit où brancher un second analyseur sans réécrire le
premier.

## Décision

Une interface commune, [`ScannerEngine`](../../../zanshin/services/scanners/base.py), qui
sépare **quoi** scanner de **comment et où** c'est exécuté. L'orchestrateur appelle
l'implémentation configurée ; le moteur Docker reste le défaut, fonctionnellement
inchangé.

Trois implémentations aujourd'hui : Docker, une API locale en side-car, OSV.

**Une méthode qu'un moteur ne sait pas faire renvoie `None`, elle n'est pas abstraite.**
`None` est la façon honnête pour un backend de dire « je ne fais pas de SAST ». Une
sixième méthode abstraite casserait les deux autres implémentations et le test de contrat
le jour où on ajoute un type d'analyse — c'est-à-dire qu'elle punirait l'extension.

## Ce qu'on a écarté

**Une API cloud tierce comme moteur par défaut.** Elle apporterait l'enrichissement et
l'analyse d'atteignabilité sans effort, mais le SBOM part chez le tiers et — pour les
analyseurs qui lisent le code, secrets et SAST — le code aussi. Le mode cloud reste
possible et strictement opt-in ; il n'est le défaut pour rien.

**Garder le couplage direct à Docker.** C'était le moins de travail immédiat. Ça figeait
l'exigence du socket Docker en production, qui est un privilège équivalent à root sur
l'hôte.

## Conséquences

Le point d'extension est au bon niveau, et il l'est resté : quand les agents distants sont
arrivés, un agent s'est révélé être un **transport** pour cette interface, pas une
abstraction supplémentaire. C'est ce qui a permis de refuser un « SDK de plugins » comme
étant la même chose écrite deux fois.

Le coût est un contrat à tenir : `tests/scanners/test_engine_contract.py` vérifie que les
trois implémentations répondent la même chose. Sans lui, les moteurs auraient dérivé.
