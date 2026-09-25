# Votre compte et le second facteur

Chaque compte peut ajouter un second facteur temporel (TOTP) à sa propre connexion, depuis
**Compte** dans la barre supérieure.

C'est distinct du MFA qu'impose votre fournisseur d'identité. Si vous vous connectez par
[authentification unique](sso.fr.md), le second facteur est l'affaire du realm et ne se configure
pas ici ; le facteur de cette page protège les comptes qui entrent par mot de passe.

## L'enrôlement se fait en deux temps, et c'est ce qui le rend sûr

Le serveur propose un secret, et **rien n'est activé tant qu'un premier code n'a pas été vérifié**.

Sans cette confirmation, une horloge décalée ou un secret mal recopié ne se verrait qu'à la
déconnexion suivante — c'est-à-dire au pire moment, par quelqu'un qui ne peut plus entrer pour le
corriger.

Un code refusé garde l'enrôlement ouvert. Six chiffres et trente secondes de vie : se tromper est
ordinaire, et redistribuer un secret neuf pour une faute de frappe obligerait à tout recopier.

## Les codes de secours ne sont montrés qu'une fois

Le serveur les chiffre et ne les rendra plus. L'écran le dit **avant** de les afficher, parce que
l'autre issue est quelqu'un qui ferme l'onglet en pensant les retrouver plus tard.

Conservez-les comme n'importe quel autre accès de secours. C'est le seul chemin de retour quand le
téléphone a disparu.

## Il n'y a pas d'image QR, et c'est dit plutôt que caché

La dessiner demande une dépendance de plus, ce qui n'est pas une décision qu'on prend en passant
dans un produit qui épingle chaque image par empreinte. Le secret est affiché en groupes de quatre
— la saisie manuelle que toute application d'authentification accepte — et l'URI `otpauth://` reste
copiable.

## Retirer le facteur exige un code

Courant ou de secours, et c'est le serveur qui l'exige. Sans cela, un poste laissé déverrouillé une
minute suffirait à désarmer le facteur qui protège le compte, ce qui viderait la protection de son
sens.

## Changer de téléphone passe par le retrait du facteur

Un nouvel enrôlement est refusé tant qu'un facteur est actif. Le remplacer sans preuve de
l'ancien permettrait à quiconque devant un poste déverrouillé de déplacer le second facteur du
compte sur son propre téléphone ; le retirer exige un code, donc le remplacer aussi.

## Un code n'ouvre qu'une fois

Un code accepté à la connexion, ou pour confirmer l'enrôlement, est refusé s'il est présenté de
nouveau, même dans ses trente secondes. Un code de secours est consommé dès qu'il est accepté, y
compris par deux connexions qui le présentent au même instant : une seule entre. Si un code que
vous venez de saisir est refusé, attendez le suivant.

## Les codes faux comptent contre le compte

Un défi de connexion meurt après trois codes faux, et le compte absorbe **cinq codes faux par
quart d'heure, tous défis confondus**. Au-delà, la connexion répond `429` avec `Retry-After`
même avec le bon mot de passe, et le bon code remet le compteur à zéro. Seul quelqu'un qui connaît
le mot de passe peut l'épuiser — si cela vous arrive sans que ce soit vous, changez de mot de passe.

Les échecs de mot de passe sont comptés par compte, quelle que soit l'orthographe du nom qui l'a
ouvert, et par adresse de l'appelant telle que le serveur la résout à travers les
proxys de confiance (`VECTISPIRE_TRUSTED_PROXIES`, voir l'[installation](../getting-started/installation.fr.md)) ; un `client_id` envoyé par le client n'est
plus lu.

## À lire aussi

- [Authentification unique](sso.fr.md) — déléguer l'authentification, et le second facteur, à un fournisseur.
- [Utilisateurs et équipes](users-and-teams.fr.md) — les rôles, et ce que chacun peut faire.
