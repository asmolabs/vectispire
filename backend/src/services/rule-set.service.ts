import { Injectable } from '@nestjs/common';
import { DataSource, EntityManager } from 'typeorm';
import { now } from '../domain/common/timestamp';
import { TYPE_SAST } from '../domain/issues/types';
import { STATE_OPEN } from '../domain/gate/policy-gate';
import {
    InvalidRuleSetError,
    type StoredRuleFile,
    type TriageImpact,
    type UploadedRuleFile,
    acceptUpload,
    hashRuleSet,
    ruleIdsOf,
    triageImpact
} from '../domain/rules/rule-set';
import { Issue, SemgrepRuleSet } from '../persistence/entities';

/**
 * Uploaded Semgrep rule sets: storing them, activating one, and serving it to executors.
 *
 * **Why this exists rather than the environment variable alone.**
 * `ZANSHIN_SEMGREP_RULES_DIR` is read by the process that scans, and `ScanRunner` is shared
 * between the built-in worker and every remote agent. The directory therefore has to be
 * provisioned on each agent's filesystem, and the control plane has no way to check that it
 * was. Two agents, one provisioned and one not, taking turns on the same target make the
 * SAST backlog resolve and reappear with each turn — silently, because the step *ran* both
 * times. A set stored here and fetched by every executor removes that asymmetry.
 *
 * The environment variable is not withdrawn: it remains the right answer for a
 * single-instance deployment that already manages a volume, and removing it would break
 * those. The precedence is settled in `ScanRunner`, and stated there.
 */
@Injectable()
export class RuleSetService {
    constructor(private readonly dataSource: DataSource) {}

    /**
     * Stores an upload. **Does not activate it.**
     *
     * The two steps are separate because activation is the destructive one: it changes what
     * the next scan looks for, and a rule that disappears takes its open issues with it. An
     * operator uploads, reads what activation would cost, and then decides.
     */
    async store(files: UploadedRuleFile[], name: string, uploadedBy: string | null): Promise<SemgrepRuleSet> {
        const stored = acceptUpload(files);
        const label = (name ?? '').trim();
        if (!label) throw new InvalidRuleSetError('A rule set needs a name.');

        const row = new SemgrepRuleSet();
        row.name = label;
        row.files = stored;
        row.contentHash = hashRuleSet(stored);
        row.ruleCount = ruleIdsOf(stored).size;
        row.fileCount = stored.length;
        row.sizeBytes = String(stored.reduce((total, file) => total + Buffer.byteLength(file.content, 'utf8'), 0));
        // `null`, not `false`: the unique index over this column is what enforces "at most
        // one active", and it only counts NULLs as distinct.
        row.isActive = null;
        row.uploadedBy = uploadedBy;
        row.uploadedAt = now();
        row.activationNote = null;

        return this.dataSource.manager.save(row);
    }

    /** Every stored set, newest first, without their content. */
    async list(): Promise<Omit<SemgrepRuleSet, 'files'>[]> {
        const rows = await this.dataSource.getRepository(SemgrepRuleSet).find({ order: { uploadedAt: 'DESC' } });
        // The files are megabytes; a listing that carried them would be a listing nobody
        // opens twice.
        return rows.map(({ files: _files, ...rest }) => rest as Omit<SemgrepRuleSet, 'files'>);
    }

    /** The active set, or `null` when only the bundled rules apply. */
    async active(): Promise<SemgrepRuleSet | null> {
        return this.dataSource.getRepository(SemgrepRuleSet).findOne({ where: { isActive: true } });
    }

    /** One stored set, files included. */
    async byId(id: number): Promise<SemgrepRuleSet | null> {
        return this.dataSource.getRepository(SemgrepRuleSet).findOneBy({ id });
    }

    /** A set by the hash an executor holds, for the fetch route. */
    async byHash(contentHash: string): Promise<SemgrepRuleSet | null> {
        return this.dataSource.getRepository(SemgrepRuleSet).findOne({ where: { contentHash } });
    }

    /**
     * What activating this set would do to the existing backlog.
     *
     * **The answer an operator has to see before clicking.** A rule id enters an issue's
     * fingerprint: a rule that is not in the new set stops being found, its issues are
     * resolved on the next scan, and their triage decisions — justifications, review dates,
     * who decided — go with them. Nothing errors, and the dashboard looks better afterwards.
     *
     * Counted from the open SAST issues that exist right now, grouped by the rule that
     * produced them, because the backlog is the authority on what has something to lose —
     * not the previously uploaded set, since rules also arrive from the bundled tree and
     * from `ZANSHIN_SEMGREP_RULES_DIR`.
     */
    async impactOf(candidate: SemgrepRuleSet): Promise<TriageImpact> {
        const current = await this.active();
        const currentIds = current ? ruleIdsOf(current.files as StoredRuleFile[]) : new Set<string>();
        const nextIds = ruleIdsOf(candidate.files as StoredRuleFile[]);

        return triageImpact(currentIds, nextIds, await this.openSastIssuesByRule());
    }

    /**
     * Activates a set, and records what the operator was told it would cost.
     *
     * In one transaction with the deactivation: the unique index makes two active rows
     * impossible, so a partial application would leave *none* active — silently falling back
     * to the bundled rule, which is the failure this whole feature exists to prevent.
     */
    async activate(id: number, note: string | null): Promise<SemgrepRuleSet> {
        return this.dataSource.transaction(async (manager: EntityManager) => {
            const target = await manager.findOneBy(SemgrepRuleSet, { id });
            if (!target) throw new InvalidRuleSetError(`No rule set with id ${id}.`);

            await manager.update(SemgrepRuleSet, { isActive: true }, { isActive: null });
            await manager.update(SemgrepRuleSet, { id }, { isActive: true, activationNote: note });

            return (await manager.findOneBy(SemgrepRuleSet, { id })) as SemgrepRuleSet;
        });
    }

    /** Returns to the bundled rules alone. */
    async deactivateAll(): Promise<void> {
        await this.dataSource.manager.update(SemgrepRuleSet, { isActive: true }, { isActive: null });
    }

    /**
     * Open SAST issues, counted per rule identifier.
     *
     * Read from `t_issue` alone: the issue carries its own `type` and `identifier`, and that
     * identifier **is** Semgrep's `check_id` — the same string, because
     * `--no-rewrite-rule-ids` stops Semgrep prefixing it with the rule file's path. Joining
     * `t_finding` to reach it would add a join for a column that is already here, and would
     * count an issue once per scan that saw it.
     */
    private async openSastIssuesByRule(): Promise<Map<string, number>> {
        const rows: { identifier: string | null; count: string }[] = await this.dataSource
            .getRepository(Issue)
            .createQueryBuilder('issue')
            .select('issue.identifier', 'identifier')
            .addSelect('COUNT(issue.id)', 'count')
            .where('issue.state = :state', { state: STATE_OPEN })
            .andWhere('issue.type = :type', { type: TYPE_SAST })
            .groupBy('issue.identifier')
            .getRawMany();

        const counts = new Map<string, number>();
        for (const row of rows) {
            // `getRawMany` short-circuits hydration: the count arrives as the driver returns
            // it, which is a string on PostgreSQL and MySQL. Reading it as a number without
            // converting would compare `"12"` against numbers elsewhere.
            if (row.identifier) counts.set(row.identifier, Number(row.count));
        }
        return counts;
    }
}
