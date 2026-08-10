/**
 * Toutes les entités portées, en un point unique.
 *
 * Le module de persistance et le test de parité de schéma lisent cette liste : ajouter
 * une entité ici la fait entrer *à la fois* dans la connexion et dans la vérification
 * qu'elle décrit bien le schéma réel. Deux listes séparées auraient fini par diverger,
 * et c'est celle du test qui aurait manqué la nouvelle entité — soit exactement la
 * moitié où l'oubli ne se voit pas.
 */
export { Agent, CREDENTIALS_DELEGATED, CREDENTIALS_LOCAL, KIND_BUILTIN, KIND_REMOTE, ONLINE_TTL_SECONDS } from './agent.entity';
export { AiReviewResult } from './ai-review-result.entity';
export { ALL_SCOPES, ApiKey, DEFAULT_SCOPES, SCOPE_AGENT, SCOPE_EXPORT, SCOPE_READ, SCOPE_SCAN } from './api-key.entity';
export { AuditLog, AuditOperation } from './audit-log.entity';
export type { AuditOperationType } from './audit-log.entity';
export { Container } from './container.entity';
export { Finding } from './finding.entity';
export { GatePolicyRow } from './gate-policy.entity';
export { Issue, STATE_OPEN, STATE_RESOLVED, TRIAGE_AFFECTED, TRIAGE_FIXED, TRIAGE_NOT_AFFECTED, TRIAGE_UNDER_REVIEW } from './issue.entity';
export { LeaderLease } from './leader-lease.entity';
export { LoginAttempt } from './login-attempt.entity';
export { OUTBOX_FAILED, OUTBOX_PENDING, OUTBOX_SENT, OutboxMessage } from './outbox-message.entity';
export { ProcessedMessage } from './processed-message.entity';
export { Repository } from './repository.entity';
export { STATUS_COMPLETED, STATUS_FAILED, STATUS_QUEUED, STATUS_RUNNING, Scan } from './scan.entity';
export { Session } from './session.entity';
export { Setting } from './setting.entity';
export { SshKey } from './ssh-key.entity';
export { ADMIN_ROLES, User, VALID_ROLES } from './user.entity';

import { Agent } from './agent.entity';
import { AiReviewResult } from './ai-review-result.entity';
import { ApiKey } from './api-key.entity';
import { AuditLog } from './audit-log.entity';
import { Container } from './container.entity';
import { Finding } from './finding.entity';
import { GatePolicyRow } from './gate-policy.entity';
import { Issue } from './issue.entity';
import { LeaderLease } from './leader-lease.entity';
import { LoginAttempt } from './login-attempt.entity';
import { OutboxMessage } from './outbox-message.entity';
import { ProcessedMessage } from './processed-message.entity';
import { Repository } from './repository.entity';
import { Scan } from './scan.entity';
import { Session } from './session.entity';
import { Setting } from './setting.entity';
import { SshKey } from './ssh-key.entity';
import { User } from './user.entity';

export const ENTITIES = [
    Agent,
    AiReviewResult,
    ApiKey,
    AuditLog,
    Container,
    Finding,
    GatePolicyRow,
    Issue,
    LeaderLease,
    LoginAttempt,
    OutboxMessage,
    ProcessedMessage,
    Repository,
    Scan,
    Session,
    Setting,
    SshKey,
    User
];
