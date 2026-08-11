import { BadRequestException, Body, Controller, Get, HttpCode, Post } from '@nestjs/common';
import { InjectEntityManager } from '@nestjs/typeorm';
import { EntityManager } from 'typeorm';
import { GateIssue, evaluate } from '../domain/gate/policy-gate';
import { RequestedPolicy } from '../domain/gate/policy-gate';
import { StoredPolicy, describeSource, resolvePolicy } from '../domain/gate/policy-resolution';
import { TARGET_CONTAINER, TARGET_REPOSITORY, buildOverview } from '../domain/gate/security-overview';
import { GatePolicyRow } from '../persistence/entities';
import { TargetRepository } from '../repositories/target.repository';
import { containerDisplayName, repositoryDisplayName } from '../domain/targets/display-name';

/**
 * Le verdict que demande un pipeline, et la posture qu'affiche l'écran Sécurité.
 *
 * **Les deux passent par le même `evaluate`.** C'est la propriété qui rend l'écran
 * digne de confiance : une agrégation SQL qui recompterait « les problèmes au-dessus du
 * seuil » serait d'accord aujourd'hui et divergerait au premier drapeau ajouté à la
 * politique — et personne ne le verrait avant qu'un pipeline et un écran ne se
 * contredisent sur le même dépôt.
 *
 * `POST` et non `GET` pour le verdict, parce que la requête porte un corps : la
 * politique demandée. Elle ne peut que **durcir** celle qui est stockée, et les
 * assouplissements refusés sont renvoyés plutôt qu'ignorés en silence — un pipeline qui
 * croit avoir désactivé une règle doit l'apprendre.
 */
@Controller('api/v1')
export class GateController {
    constructor(
        @InjectEntityManager() private readonly manager: EntityManager,
        private readonly targets: TargetRepository = new TargetRepository()
    ) {}

    @Post('gate')
    @HttpCode(200)
    async evaluateGate(@Body() body: Record<string, unknown>) {
        const repositoryId = optionalInt(body.repository_id);
        const containerId = optionalInt(body.container_id);
        if ((repositoryId === null) === (containerId === null)) {
            throw new BadRequestException('Indiquez exactement un « repository_id » ou un « container_id ».');
        }

        const kind = repositoryId !== null ? TARGET_REPOSITORY : TARGET_CONTAINER;
        const targetId = repositoryId ?? containerId!;

        const [policies, issues] = await Promise.all([this.targets.findActivePolicies(this.manager), this.targets.findOpenForGate(this.manager)]);
        const byScope = indexPolicies(policies);

        const resolved = resolvePolicy(
            { forTarget: byScope.get(`${kind}:${targetId}`) ?? null, global: byScope.get('global:0') ?? null },
            requestedPolicy(body)
        );

        const scoped = issues.filter((issue) => (kind === TARGET_REPOSITORY ? issue.repoId === targetId : issue.containerId === targetId));
        const verdict = evaluate(scoped as unknown as GateIssue[], resolved.policy);

        // 200 même quand le verdict est rouge : la requête a abouti, c'est sa *réponse*
        // qui est négative. Un 4xx ici ferait confondre « votre dépôt a des
        // vulnérabilités » avec « votre appel est mal formé ».
        return {
            passed: verdict.passed,
            evaluated: verdict.evaluated,
            counts_by_severity: verdict.countsBySeverity,
            violations: verdict.violations,
            policy: { ...resolved.policy, source: resolved.source, version: resolved.version, description: describeSource(resolved) },
            ignored_relaxations: resolved.ignoredRelaxations
        };
    }

    /** La posture de toutes les cibles — ce qu'affiche l'écran Sécurité. */
    @Get('security/overview')
    async overview() {
        const [repositories, containers, policies, issues, scansByRepository, scansByContainer] = await Promise.all([
            this.targets.findRepositories(this.manager),
            this.targets.findContainers(this.manager),
            this.targets.findActivePolicies(this.manager),
            this.targets.findOpenForGate(this.manager),
            this.targets.findLatestScans(this.manager, 'repo_id'),
            this.targets.findLatestScans(this.manager, 'container_id')
        ]);

        return buildOverview({
            repositories: repositories.map((repository) => ({ id: repository.id, name: repositoryDisplayName(repository) })),
            containers: containers.map((container) => ({ id: container.id, name: containerDisplayName(container) })),
            policies: policies.map((row) => ({ targetKind: row.targetKind, targetId: row.targetId, policy: toStoredPolicy(row) })),
            openIssues: issues as unknown as (GateIssue & { repoId: number | null; containerId: number | null })[],
            latestScanByRepository: toLatest(scansByRepository),
            latestScanByContainer: toLatest(scansByContainer)
        });
    }
}

function indexPolicies(rows: GatePolicyRow[]): Map<string, StoredPolicy> {
    const byScope = new Map<string, StoredPolicy>();
    for (const row of rows) byScope.set(`${row.targetKind}:${row.targetId}`, toStoredPolicy(row));
    return byScope;
}

export function toStoredPolicy(row: GatePolicyRow): StoredPolicy {
    return {
        failOnSeverity: row.failOnSeverity,
        failOnKev: row.failOnKev,
        fixableOnly: row.fixableOnly,
        includeTriaged: row.includeTriaged,
        includeAiReview: row.includeAiReview,
        version: row.version
    };
}

/**
 * Ce que l'appelant a **réellement envoyé**.
 *
 * La présence d'une clé compte, pas sa valeur : sans cette distinction, tout appelant
 * omettant `fail_on_severity` semblerait demander le défaut du schéma et s'entendrait
 * répondre que sa requête a été refusée, à chaque appel.
 */
function requestedPolicy(body: Record<string, unknown>): RequestedPolicy {
    const requested: RequestedPolicy = {};
    if ('fail_on_severity' in body) requested.failOnSeverity = body.fail_on_severity === null ? null : String(body.fail_on_severity);
    if ('fail_on_kev' in body) requested.failOnKev = Boolean(body.fail_on_kev);
    if ('fixable_only' in body) requested.fixableOnly = Boolean(body.fixable_only);
    if ('include_triaged' in body) requested.includeTriaged = Boolean(body.include_triaged);
    if ('include_ai_review' in body) requested.includeAiReview = Boolean(body.include_ai_review);
    return requested;
}

export function toLatest(scans: Map<number, { id: number; status: string | null; created_at?: Date; createdAt?: Date }>) {
    const latest = new Map<number, { id: number; status: string | null; createdAt: Date | null }>();
    for (const [id, scan] of scans) {
        // La requête brute rend les colonnes telles que la base les nomme.
        latest.set(id, { id: scan.id, status: scan.status, createdAt: scan.createdAt ?? scan.created_at ?? null });
    }
    return latest;
}

function optionalInt(value: unknown): number | null {
    if (value === null || value === undefined) return null;
    const parsed = Number(value);
    return Number.isFinite(parsed) ? Math.trunc(parsed) : null;
}
