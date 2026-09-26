import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { ProjectView, Schema, SolutionTree, SolutionView } from '../api.models';

/**
 * Solutions, the projects they hold and the repositories filed in them (decision 0023).
 *
 * One stateless client per domain, named `*.api.ts` / `*Api` so that it is never mistaken for a
 * `*.service.ts` or a store holding state, and so that `scripts/check-dead-api-methods.mjs` knows
 * which files declare the API surface. No absolute URL: the development server proxies `/api`
 * (`proxy.conf.json`) and production serves both from one origin, which is what lets the CSP stay
 * on `connect-src 'self'`.
 *
 * Reading the tree takes any account and answers only what that account may see; every write is
 * an administrator's, and the server is the authority on that — the screens only avoid offering it.
 */
@Injectable({ providedIn: 'root' })
export class SolutionsApi {
    private readonly http = inject(HttpClient);

    solutionTree(): Observable<SolutionTree> {
        return this.http.get<SolutionTree>('/api/v1/solutions');
    }

    createSolution(solution: Schema<'SolutionRequest'>): Observable<SolutionView> {
        return this.http.post<SolutionView>('/api/v1/solutions', solution);
    }

    /** An absent field is left alone; an empty description clears it. */
    updateSolution(id: number, changes: Schema<'SolutionRequest'>): Observable<SolutionView> {
        return this.http.patch<SolutionView>(`/api/v1/solutions/${id}`, changes);
    }

    /** 409 while the solution still holds a project — the server's sentence says so. */
    deleteSolution(id: number): Observable<void> {
        return this.http.delete<void>(`/api/v1/solutions/${id}`);
    }

    createProject(solutionId: number, project: Schema<'ProjectRequest'>): Observable<ProjectView> {
        return this.http.post<ProjectView>(`/api/v1/solutions/${solutionId}/projects`, project);
    }

    updateProject(id: number, changes: Schema<'ProjectChange'>): Observable<ProjectView> {
        return this.http.patch<ProjectView>(`/api/v1/projects/${id}`, changes);
    }

    /** Its repositories return to "no project" and every grant naming it is revoked. */
    deleteProject(id: number): Observable<void> {
        return this.http.delete<void>(`/api/v1/projects/${id}`);
    }

    /**
     * Files a repository into a project, **moving** it out of the one it was in. A move is an access
     * change: a project grant covers what the project holds at the time of each request.
     */
    fileRepository(projectId: number, repositoryId: number): Observable<void> {
        return this.http.put<void>(`/api/v1/projects/${projectId}/repositories/${repositoryId}`, null);
    }

    /** Back to "no project". */
    unfileRepository(projectId: number, repositoryId: number): Observable<void> {
        return this.http.delete<void>(`/api/v1/projects/${projectId}/repositories/${repositoryId}`);
    }
}
