import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { User } from './auth/auth.service';

export interface RepositorySummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  negligible: number;
  unknown: number;
  total: number;
}

export interface Scan {
  id: number;
  branch: string;
  status: string;
  sbom?: any;
  cves?: any;
  summary?: RepositorySummary;
  durationMs?: number;
  findingsCount?: number;
  error?: string;
  subPath?: string;
  version?: string;
  projectType?: string;
  createdAt: string;
}

export interface SSHKey {
  id: string;
  name: string;
  publicKey?: string;
  createdAt: string;
}

export interface Repository {
  id: number;
  url: string;
  branch: string;
  subPath: string;
  name?: string;
  scans: Scan[];
  sshKeyId?: string;
  scanIntervalMinutes?: number;
  scanCron?: string;
}

export interface Container {
  id: number;
  registry?: string;
  imageName: string;
  tag: string;
  scanIntervalMinutes?: number;
  scanCron?: string;
  lastScheduledScanAt?: string;
  scans: Scan[];
}

export interface VexDecision {
  id?: number;
  vulnerabilityId: string;
  packageName: string;
  purl?: string;
  status: 'not_affected' | 'affected' | 'fixed' | 'under_investigation';
  justification?: string;
  response?: string;
  comment?: string;
  updatedAt?: string;
}

export interface ApiKey {
  id: string;
  name: string;
  lastUsedAt?: string;
  createdAt: string;
}

@Injectable({
  providedIn: 'root'
})
export class ApiService {
  private http = inject(HttpClient);
  private baseUrl = 'http://localhost:8080/api/repository';
  private sshUrl = 'http://localhost:8080/api/ssh-keys';
  private usersUrl = 'http://localhost:8080/api/users';
  private apiKeysUrl = 'http://localhost:8080/api/auth/api-keys';
  private containersUrl = 'http://localhost:8080/api/containers';

  getRepositories() {
    return this.http.get<Repository[]>(this.baseUrl);
  }

  addRepository(url: string, branch: string, sshKeyId?: string, name?: string, subPath?: string) {
    return this.http.post<Repository>(this.baseUrl, { url, branch, sshKeyId, name, subPath });
  }

  deleteRepository(id: number) {
    return this.http.delete(`${this.baseUrl}/${id}`);
  }

  updateRepository(id: number, data: Partial<Repository>) {
    return this.http.patch<Repository>(`${this.baseUrl}/${id}`, data);
  }

  deleteScan(repoId: number, scanId: number) {
    return this.http.delete(`${this.baseUrl}/${repoId}/scan/${scanId}`);
  }

  // SSH Key Management
  getSSHKeys() {
    return this.http.get<SSHKey[]>(this.sshUrl);
  }

  addSSHKey(name: string, privateKey: string, publicKey?: string, id?: string) {
    return this.http.post<SSHKey>(this.sshUrl, { name, privateKey, publicKey, id });
  }

  deleteSSHKey(id: string) {
    return this.http.delete(`${this.sshUrl}/${id}`);
  }

  generateSSHKey() {
    return this.http.post<{ publicKey: string; privateKey: string }>(`${this.sshUrl}/generate`, {});
  }

  triggerRescan(repoId: number, branch: string, subPath?: string) {
    return this.http.post<Scan>(`${this.baseUrl}/${repoId}/scan`, { branch, subPath });
  }

  // --- Users ---
  getUsers() {
    return this.http.get<User[]>(this.usersUrl);
  }

  updateUserRole(userId: number, role: 'admin' | 'user') {
    return this.http.patch<User>(`${this.usersUrl}/${userId}/role`, { role });
  }

  updateUserStatus(userId: number, isActive: boolean) {
    return this.http.patch<User>(`${this.usersUrl}/${userId}/active`, { isActive });
  }

  // --- Containers ---
  getContainers() {
    return this.http.get<Container[]>(this.containersUrl);
  }

  addContainer(imageName: string, tag: string = 'latest', registry?: string) {
    return this.http.post<Container>(this.containersUrl, { imageName, tag, registry });
  }

  updateContainer(id: number, data: { scanIntervalMinutes?: number; scanCron?: string }) {
    return this.http.patch<Container>(`${this.containersUrl}/${id}`, data);
  }

  deleteContainer(id: number) {
    return this.http.delete(`${this.containersUrl}/${id}`);
  }

  triggerContainerScan(id: number) {
    return this.http.post<Scan>(`${this.containersUrl}/${id}/scan`, {});
  }
  
  deleteContainerScan(containerId: number, scanId: number) {
    return this.http.delete(`${this.containersUrl}/${containerId}/scans/${scanId}`);
  }

  getVexDecisions(repoId: number) {
    return this.http.get<VexDecision[]>(`${this.baseUrl}/${repoId}/vex`);
  }

  upsertVexDecision(repoId: number, decision: VexDecision) {
    return this.http.post<VexDecision>(`${this.baseUrl}/${repoId}/vex`, { ...decision, repositoryId: repoId });
  }

  exportOpenVex(repoId: number) {
    window.location.href = `${this.baseUrl}/${repoId}/openvex`;
  }

  // API Key Management
  getApiKeys() {
    return this.http.get<ApiKey[]>(this.apiKeysUrl);
  }

  createApiKey(name: string) {
    return this.http.post<{ apiKey: ApiKey; rawKey: string }>(this.apiKeysUrl, { name });
  }

  deleteApiKey(id: string) {
    return this.http.delete(`${this.apiKeysUrl}/${id}`);
  }
}

