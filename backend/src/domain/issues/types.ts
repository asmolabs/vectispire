/**
 * Les types de constat, et la cloison entre ce qui bloque et ce qui ne bloque pas.
 *
 * **`quality` ne fait jamais échouer une compilation.** Ce n'est pas un réglage : un
 * drapeau ferait de cette phrase un mensonge dès qu'on le décocherait. C'est aussi la
 * raison pour laquelle ce type est exclu des compteurs de tête d'écran — le jour de la
 * mise en service du SAST, un dépôt ordinaire passe de quelques dizaines de
 * vulnérabilités à quelques milliers de constats de qualité, et un compteur qui les
 * mélange transforme ce chiffre en bruit que plus personne ne regarde.
 */
export const TYPE_VULNERABILITY = 'vulnerability';
export const TYPE_SECRET = 'secret';
export const TYPE_IAC = 'iac';
export const TYPE_LICENSE = 'license';
export const TYPE_EOL = 'eol';
export const TYPE_SAST = 'sast';
export const TYPE_QUALITY = 'quality';

/** Les types qui comptent dans une posture de sécurité. `quality` en est absent, et c'est
 *  tout l'objet de cette liste. */
export const SECURITY_TYPES = [TYPE_VULNERABILITY, TYPE_SECRET, TYPE_IAC, TYPE_LICENSE, TYPE_EOL, TYPE_SAST] as const;
