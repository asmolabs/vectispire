-- Le défi MFA, sorti de la mémoire du processus.
--
-- **Il vivait dans une 'ConcurrentHashMap' du contrôleur, donc dans une seule instance.** Le
-- déploiement multi-instance est documenté et supporté — quatre tâches périodiques, un bail de
-- leader, une section entière de '04-runtime-and-deployment' — mais la MFA n'y survivait pas : le
-- mot de passe est échangé contre un jeton de défi sur l'instance A, le code à six chiffres arrive
-- sur l'instance B, et B ne connaît pas ce jeton. La réponse était « votre défi a expiré »,
-- immédiatement, sans rien dans les journaux qui la distingue d'un vrai dépassement de délai.
--
-- Le contrôleur le disait dans un commentaire — « needs session affinity on /api/v1/auth/** until
-- this moves to the database » — et rien d'autre ne le disait, surtout pas le document que lit
-- celui qui monte une seconde réplique. C'est ce déplacement-là.
--
-- **C'est le hachage du jeton qui est stocké, jamais le jeton**, exactement comme 't_session'
-- depuis V5 : ce qui est indexé ne sert à personne qui lirait la table. Les tentatives sont
-- comptées sur la ligne, parce que c'est le défi que l'attaquant tient et c'est le défi qui est
-- détruit au troisième échec — compter sur le compte permettrait de verrouiller un utilisateur
-- légitime en devinant mal à sa place.
--
-- 'on delete cascade' : supprimer un compte doit emporter le défi en cours, comme il emporte déjà
-- ses sessions.
--
-- L'index sur l'expiration sert la purge, pas une lecture : la lecture se fait par clé primaire.

create table t_mfa_challenge (
    token_hash varchar(64) not null primary key,
    user_id bigint not null references t_user(id) on delete cascade,
    expires_at datetime(6) not null,
    attempts integer not null default 0,
    user_agent varchar(255),
    ip_address varchar(64)
);

create index idx_mfa_challenge_expires on t_mfa_challenge (expires_at);
