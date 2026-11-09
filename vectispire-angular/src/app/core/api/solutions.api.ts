import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpResponse } from '@angular/common/http';
import { Observable } from 'rxjs';
import {
    ConsolidatedInventory,
    ProjectDetail,
    ProjectView,
    Schema,
    ScopeCompliance,
    SolutionTree,
    SolutionView
} from '../api.models';
import { DocumentsApi } from './documents.api';

/**
 * Solutions, the projects they hold and the repositories and images filed in them (decision 0023).
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
    private readonly documents = inject(DocumentsApi);

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

    /** The solution's compliance and score over its visible targets; 404 when the reader sees none of it. */
    solutionCompliance(id: number): Observable<ScopeCompliance> {
        return this.http.get<ScopeCompliance>(`/api/v1/solutions/${id}/compliance`);
    }

    /**
     * One project, read on its own. 404 for a project that does not exist and for one the reader sees
     * nothing of alike — a refusal indistinguishable from an absence.
     */
    project(id: number): Observable<ProjectDetail> {
        return this.http.get<ProjectDetail>(`/api/v1/projects/${id}`);
    }

    projectCompliance(id: number): Observable<ScopeCompliance> {
        return this.http.get<ScopeCompliance>(`/api/v1/projects/${id}/compliance`);
    }

    /** The components of the project's visible targets, merged, with the inventory state of each target. */
    projectComponents(id: number): Observable<ConsolidatedInventory> {
        return this.http.get<ConsolidatedInventory>(`/api/v1/projects/${id}/components`);
    }

    /** The same list as a CycloneDX 1.5 document with its VEX statements — a blob, for the interceptor's token. */
    projectCycloneDx(id: number): Observable<HttpResponse<Blob>> {
        return this.documents.downloadDocument(`/api/v1/cyclonedx/projects/${id}/cyclonedx-vex.json`);
    }

    createProject(solutionId: number, project: Schema<'ProjectRequest'>): Observable<ProjectView> {
        return this.http.post<ProjectView>(`/api/v1/solutions/${solutionId}/projects`, project);
    }

    updateProject(id: number, changes: Schema<'ProjectChange'>): Observable<ProjectView> {
        return this.http.patch<ProjectView>(`/api/v1/projects/${id}`, changes);
    }

    /** Its repositories and images return to "no project" and every grant naming it is revoked. */
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

    /**
     * Files a container image into a project, moving it like a repository — and, like one, an access
     * change: a project grant covers the images the project holds too (decision 0023, amendment).
     */
    fileContainer(projectId: number, containerId: number): Observable<void> {
        return this.http.put<void>(`/api/v1/projects/${projectId}/containers/${containerId}`, null);
    }

    /** Back to "no project"; 404 when the image is not in that project. */
    unfileContainer(projectId: number, containerId: number): Observable<void> {
        return this.http.delete<void>(`/api/v1/projects/${projectId}/containers/${containerId}`);
    }
}
