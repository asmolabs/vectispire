/**
 * Les images de scanner, **épinglées par condensé**.
 *
 * Ces images *sont* la chaîne d'approvisionnement de Zanshin : un outil qui audite celle
 * des autres ne peut pas tirer `:latest` et exécuter ce qui vient. Un condensé fait de la
 * mise à jour un acte délibéré et relisible, au lieu d'un changement qui survient un
 * matin sans que personne l'ait décidé.
 *
 * Les condensés sont ceux de l'index multi-architecture, donc ils sélectionnent toujours
 * la bonne architecture selon l'hôte. Pour les mettre à jour :
 * `docker buildx imagetools inspect <image>:latest`.
 *
 * Chaque image reste surchargeable par variable d'environnement — un opérateur qui
 * héberge un miroir interne en a besoin, et le lui refuser le pousserait à modifier le
 * code.
 */

export const SYFT_IMAGE = process.env.ZANSHIN_SYFT_IMAGE ?? 'anchore/syft@sha256:1288ea4c8b38767b4e620c1e312c8cb26b6e887a99b4f07ab6cd19fc6f225026';

export const GRYPE_IMAGE = process.env.ZANSHIN_GRYPE_IMAGE ?? 'anchore/grype@sha256:1e71065c0a4cff3e6bd3b8add525ffac4343eb4971694eb90a31cf6d4d3e85db';

export const GITLEAKS_IMAGE =
    process.env.ZANSHIN_GITLEAKS_IMAGE ?? 'zricethezav/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f';

export const CHECKOV_IMAGE =
    process.env.ZANSHIN_CHECKOV_IMAGE ?? 'bridgecrew/checkov@sha256:12a62da01af22654883aee3b9da18ba4297f123f5122663bf65235db37934144';

export const SEMGREP_IMAGE = process.env.ZANSHIN_SEMGREP_IMAGE ?? 'semgrep/semgrep@sha256:bdf7013b2c3634a487671158da77c554f531742326b543a9464d2adf6c433ac8';
