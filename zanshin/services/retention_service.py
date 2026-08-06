"""Retention of the raw scanner payloads.

`Scan.sbom` and `Scan.cves` hold each scan's untouched tool output. One container
scan of a JRE base image is ~2.5 MB of SBOM; the development database reached
18 MB for thirteen scans, and nothing ever removed anything. Left alone, the
database grows monotonically for as long as the scheduler runs — which, since
wave 2, is forever.

What is pruned and what is kept is the whole design:

- **Pruned**: `sbom` and `cves`, the raw blobs. They exist for audit ("what
  exactly did Syft report that day"), and that value decays quickly.
- **Kept, always**: `Scan.summary` and `findings_count` (the per-scan numbers the
  history table shows), every `Finding` row, and every `Issue`. The normalized
  projection *is* the durable record — that was the point of building it — so
  pruning a blob costs no history, no triage and no delta.

A retention policy that silently dropped the most recent payloads would be
useless for the one thing they're for, so the newest N scans of each target are
always exempt regardless of age.
"""
import logging
from datetime import timedelta
from typing import List, NamedTuple, Optional

from sqlalchemy import or_
from sqlalchemy.orm import Session

from zanshin.clock import utcnow
from zanshin.models.scan import Scan
from zanshin.services.settings_service import SettingsService

logger = logging.getLogger(__name__)

SETTING_KEY_RETENTION_KEEP_PER_TARGET = "retention_keep_per_target"
SETTING_KEY_RETENTION_MAX_AGE_DAYS = "retention_max_age_days"

# Keep the raw output of the last 10 scans of each target, and of anything from
# the last 90 days. Generous defaults: the point is to bound growth, not to be
# frugal, and an operator investigating a regression looks at recent scans.
DEFAULT_KEEP_PER_TARGET = 10
DEFAULT_MAX_AGE_DAYS = 90

# 0 in either setting means "no limit on that axis"; both at 0 disables pruning.
UNLIMITED = 0


class PruneResult(NamedTuple):
    scans_pruned: int
    bytes_freed: int


class RetentionService:
    def __init__(self, settings_service: SettingsService):
        self.settings_service = settings_service

    def keep_per_target(self) -> int:
        return self._int_setting(SETTING_KEY_RETENTION_KEEP_PER_TARGET, DEFAULT_KEEP_PER_TARGET)

    def max_age_days(self) -> int:
        return self._int_setting(SETTING_KEY_RETENTION_MAX_AGE_DAYS, DEFAULT_MAX_AGE_DAYS)

    def _int_setting(self, key: str, default: int) -> int:
        raw = self.settings_service.get_setting(key, str(default))
        try:
            value = int(raw)
        except (TypeError, ValueError):
            logger.warning("Setting '%s' is not an integer (%r) — using %d", key, raw, default)
            return default
        return max(UNLIMITED, value)

    def is_enabled(self) -> bool:
        return self.keep_per_target() != UNLIMITED or self.max_age_days() != UNLIMITED

    def find_prunable(self, db: Session) -> List[Scan]:
        """Scans whose raw payloads may be dropped.

        A scan qualifies when it is *both* outside the "keep the last N of this
        target" window and older than the age limit. Requiring both means a
        target scanned twice a year keeps its payloads, and a target scanned
        hourly still gets bounded — neither rule alone does that.
        """
        keep = self.keep_per_target()
        max_age = self.max_age_days()
        if not self.is_enabled():
            return []

        # Only rows that still carry a payload; the column check is what makes
        # this cheap to run on every scheduler tick.
        candidates = (
            db.query(Scan)
            .filter(or_(Scan.sbom.isnot(None), Scan.cves.isnot(None)))
            .order_by(Scan.created_at.desc(), Scan.id.desc())
            .all()
        )

        cutoff = utcnow() - timedelta(days=max_age) if max_age != UNLIMITED else None
        seen_per_target: dict = {}
        prunable = []
        for scan in candidates:
            # Rows pruned before the `none_as_null` fix hold the JSON literal
            # `null`, which satisfies `IS NOT NULL` in SQL but is `None` here.
            if not scan.sbom and not scan.cves:
                continue
            target = ("repo", scan.repo_id) if scan.repo_id else ("container", scan.container_id)
            rank = seen_per_target.get(target, 0)
            seen_per_target[target] = rank + 1

            if keep != UNLIMITED and rank < keep:
                continue  # inside the "most recent" window
            if cutoff is not None and scan.created_at and scan.created_at >= cutoff:
                continue  # too recent to prune
            prunable.append(scan)
        return prunable

    def prune(self, db: Session, vacuum: bool = True) -> PruneResult:
        """Drop the raw payloads of every prunable scan.

        Returns what was freed. `vacuum` reclaims the space on disk: SQLite keeps
        emptied pages for reuse, so without it the file never shrinks and the
        operator sees no effect at all. Skipped when nothing was pruned, since a
        VACUUM rewrites the whole database and takes a write lock.
        """
        prunable = self.find_prunable(db)
        if not prunable:
            return PruneResult(0, 0)

        freed = 0
        for scan in prunable:
            freed += _payload_size(scan)
            scan.sbom = None
            scan.cves = None
        db.commit()

        logger.info(
            "Retention: dropped raw payloads of %d scan(s), ~%.1f MB (keep=%d per target, max age=%d days)",
            len(prunable), freed / 1_048_576, self.keep_per_target(), self.max_age_days(),
        )

        if vacuum:
            try:
                # Outside the ORM transaction: SQLite refuses VACUUM inside one.
                db.commit()
                db.connection().exec_driver_sql("VACUUM")
                logger.info("Retention: database vacuumed")
            except Exception:
                # Losing the reclaim is acceptable; failing the tick is not.
                logger.warning("Retention: VACUUM failed — space will be reused, not returned", exc_info=True)

        return PruneResult(len(prunable), freed)


def _payload_size(scan: Scan) -> int:
    """Rough serialized size of a scan's raw payloads, for reporting only.

    `len(str(...))` rather than a real JSON dump: this figure exists to tell an
    operator "roughly 40 MB freed", and paying a full re-serialization of every
    blob to refine a log line would defeat the purpose.
    """
    return sum(len(str(payload)) for payload in (scan.sbom, scan.cves) if payload)
