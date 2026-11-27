import { Observable, concatMap, first, from, map, of, switchMap } from 'rxjs';
import type { ScansApi } from '../../core/api/scans.api';
import type { ScanSummary } from '../../core/api.models';

/**
 * How many completed scans are opened looking for an SBOM. The list does not say which scan has one,
 * so each candidate costs a read of its detail; a completed scan without an SBOM is one whose
 * inventory step failed, and five of those in a row is a repository to look at, not a reason to read
 * fifty details.
 */
export const SBOM_LOOKBACK = 5;

/** The scan a repository's "latest SBOM" comes from, or why there is none. */
export type LatestSbom =
    | {
          state: 'found';
          scan: ScanSummary;
          /**
           * The newest completed scan, when it is not `scan`: it had no SBOM, and the screen says the
           * documents come from an older one rather than handing them over as the latest.
           */
          newerWithout: ScanSummary | null;
      }
    | { state: 'no_completed' }
    | { state: 'no_sbom'; examined: number };

/**
 * The newest completed scan of a repository that carries an SBOM — the rule of the CLI's
 * `sbom --repo-id` (the latest completed among the fifty newest, since a pending or running scan has
 * no SBOM yet and a failed one never will), with the SBOM checked rather than met as a 404.
 *
 * Only routes that apply the caller's visibility: `GET /api/v1/scans?repo_id=` lists what the caller
 * may see, newest first, and `GET /api/v1/scans/{id}` says `hasSbom`. The details are read one at a
 * time and the walk stops at the first SBOM, so the usual case costs two requests.
 */
export function latestSbom(scans: ScansApi, repositoryId: number): Observable<LatestSbom> {
    return scans.scansOf(repositoryId).pipe(
        switchMap((list): Observable<LatestSbom> => {
            const completed = list.filter((scan) => scan.status === 'completed');
            if (completed.length === 0) return of({ state: 'no_completed' });
            const candidates = completed.slice(0, SBOM_LOOKBACK);
            return from(candidates).pipe(
                concatMap((candidate) => scans.scan(candidate.id)),
                first((detail) => detail.hasSbom, null),
                map((detail): LatestSbom => {
                    if (!detail) return { state: 'no_sbom', examined: candidates.length };
                    const newest = completed[0];
                    return {
                        state: 'found',
                        scan: detail.scan,
                        newerWithout: newest.id === detail.scan.id ? null : newest
                    };
                })
            );
        })
    );
}
