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

## À lire aussi

- [Authentification unique](sso.fr.md) — déléguer l'authentification, et le second facteur, à un fournisseur.
- [Utilisateurs et équipes](users-and-teams.fr.md) — les rôles, et ce que chacun peut faire.
