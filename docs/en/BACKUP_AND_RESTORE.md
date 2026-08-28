# Backup and restore

*Version française : [`docs/fr/BACKUP_AND_RESTORE.fr.md`](../fr/BACKUP_AND_RESTORE.fr.md).*

A backup procedure nobody has executed is a belief. This page is the procedure;
[`scripts/restore-drill.sh`](../../scripts/restore-drill.sh) is the proof, and it runs nightly.

## 1. The three states, and only one of them is obvious

| | Where it lives | What is lost with it |
|---|---|---|
| **The database** | `vectispire_mysql_data` | Targets, findings, triage decisions, users, API keys, the audit table |
| **The audit mirror** | `vectispire_audit` | The independent copy of the audit log — see §5 |
| **`ENCRYPTION_KEY`** | **Neither of them** | The ability to read anything the database keeps sealed |

The third row is the one that ends companies. The key is supplied from the environment or
`ENCRYPTION_KEY_FILE`; it is deliberately not in any volume, so a byte-perfect backup of both
volumes, restored without it, gives a control plane that **boots, serves, and cannot read a single
deployment key, registry credential or ticketing token**. Nothing about that restore looks like a
failure until somebody launches a scan.

## 2. Backing up

**The database — a dump, not a volume copy.** Copying `/var/lib/mysql` from under a running
engine captures a half-written page as readily as a whole one.

```bash
docker exec vectispire-db mysqldump -u vectispire -p"$MYSQL_PASSWORD" \
  --single-transaction --routines --triggers vectispire > vectispire-$(date +%F).sql
```

`--single-transaction` is what makes it consistent without locking the tables the control plane is
writing to.

**The audit mirror — separately, and somewhere the control plane cannot write.** It is an
append-only NDJSON file. A plain copy is enough:

```bash
docker run --rm -v vectispire_audit:/audit:ro -v "$PWD:/out" alpine \
  cp /audit/audit.ndjson /out/audit-$(date +%F).ndjson
```

*Separately* is not a formality. The mirror's entire value is that it is not the table. A backup
that captures both at one instant and restores both together produces two copies that agree
**because they were restored together**, not because nothing was tampered with. §5 is the whole
argument.

**The key — not here.** `ENCRYPTION_KEY` belongs in whatever holds your other secrets, with a
custody trail. If it is in the same archive as the database, the archive is a plaintext database
with extra steps. See [`KEY_ROTATION.md`](KEY_ROTATION.md).

## 3. Restoring

Into an **empty** engine — loading a dump over an existing schema merges two states and produces
one that never existed.

```bash
docker compose down
docker volume rm vectispire_mysql_data
docker compose up -d db          # recreates the volume, empty
# wait for it to accept connections, then:
docker exec -i vectispire-db mysql -u vectispire -p"$MYSQL_PASSWORD" vectispire < vectispire-2026-08-27.sql
docker compose up -d
```

Do **not** restore `vectispire_audit` at the same time. Leave the live mirror in place. §5.

## 4. The key, and the failure mode the drill does not cover

The nightly drill proves the dump restores and the audit chain survives. It does not prove the
restore is *readable*, because that depends on a value that is not in the backup.

Before treating a restore as complete, with a person watching:

1. Sign in and open a target that has a deployment key attached.
2. Launch a scan on it.

A scan that authenticates is the only evidence that the key you restored under is the key the data
was written under. **A control plane with the wrong key is healthy on every dashboard.** If the
scan fails to authenticate and the key is gone, the sealed columns are gone with it — restore the
key from custody, or re-enter every credential by hand. There is no third option, and that is the
property working: it is what makes a stolen database worth nothing.

## 5. Reading the verification after a restore

`GET /api/v1/audit-log/verify` — on the screen, the *Audit log* page's verification banner.

After restoring an older database while keeping the live mirror, the honest result is **not**
"intact":

```json
{"total":5,"intact":false,"broken":null,"mirrored":true,"missingFromTable":5,"missingFromMirror":0}
```

Read it as: the chain holds (`broken: null` — no row was altered), and the mirror holds five
entries the restored table does not. **That number is the restore's own receipt.** It is how many
audited actions happened between the dump and the restore, and it should be roughly what you
expect from the elapsed time. If it is far larger, your dump is older than you thought.

Now the same restore with the mirror restored alongside it — which is what a naive "restore
everything" does:

```json
{"total":7,"intact":true,"broken":null,"mirrored":true,"missingFromTable":0,"missingFromMirror":5}
```

**`intact: true`, over five audit entries that no longer exist anywhere.** The loss did not become
smaller; the only witness to it was overwritten. This is not a defect in the verification —
`intact` is `broken == null && missingFromTable == 0` deliberately, because `missingFromMirror` has
innocent explanations (rows predating the mirror, a mirror that could not be reached) and an
integrity alarm that cries wolf is one nobody reads. But it means one thing for an operator:

> **After a restore, `intact` is not the check. Read `missingFromMirror` as well.** A non-zero
> value in the hours after a restore means you restored the mirror too, and you no longer have an
> independent record of what the database lost.

Both figures above are printed by the drill on every run. They are not illustrations.

## 6. The drill

```bash
scripts/restore-drill.sh
```

It builds nothing of yours and touches no deployment: every container, network and volume it
creates carries a `drill-` prefix, and it refuses to start otherwise. It stands up a control
plane, takes a dump, performs audited actions *after* the dump, restores into a fresh engine, and
asserts what §5 describes — including the blind case, which must report `intact: true`. If that
assertion ever fails, the hazard has changed shape and this page is describing something else.

It runs in [`nightly.yml`](../../.github/workflows/nightly.yml). A restore procedure verified once
is a procedure verified on the code of that day.
