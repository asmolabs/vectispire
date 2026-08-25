# 0011 — Liquibase reste, et le DDL structurel est écrit à la main

**Date :** 2026-08-22 · **Statut :** **remplacé** par [0013](0013-flyway-multi-dialect-migrations.md) on 2026-08-22 · **Décideur :** Laurent Boucher

## Contexte & Décision

Le portage est arrivé avec Liquibase et un changelog agnostique de la base : le schéma décrit une
fois, traduit par moteur par l'outil. Le DDL structurel que le changelog ne savait pas exprimer
devait être écrit à la main à côté.

## Pourquoi elle était fausse

**Les exceptions écrites à la main n'étaient pas le cas marginal ; elles étaient la partie
porteuse.** Deux d'entre elles ont tranché, toutes deux consignées dans la
[0013](0013-flyway-multi-dialect-migrations.md) :

* un `DATETIME` nu sur MySQL tronque à la seconde, et la chaîne d'audit hache un horodatage
  canonicalisé à la milliseconde — l'abstraction se trompant sur ce type fait donc échouer un
  contrôle de sécurité à sa *propre* vérification d'intégrité, en signalant une altération qui n'a
  jamais eu lieu ;
* les clés étrangères et le comportement en cascade diffèrent assez entre moteurs pour que le DDL
  généré doive de toute façon être relu moteur par moteur.

Dès lors que les instructions générées doivent être relues par moteur, l'abstraction se tient entre
l'auteur et une instruction qu'il est déjà en train de lire. La 0013 l'a retirée.
