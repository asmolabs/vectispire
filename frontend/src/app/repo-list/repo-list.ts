import { Component, Input, Output, EventEmitter, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Repository, Scan } from '../api';
import { AuthService } from '../auth/auth.service';
import { DataViewModule } from 'primeng/dataview';
import { ButtonModule } from 'primeng/button';
import { TagModule } from 'primeng/tag';
import { AccordionModule } from 'primeng/accordion';
import { TooltipModule } from 'primeng/tooltip';


@Component({
  selector: 'app-repo-list',
  standalone: true,
  imports: [CommonModule, DataViewModule, ButtonModule, TagModule, TooltipModule],
  template: `
    <div class="repo-list">
      <p-dataView [value]="repositories" [rows]="10" [paginator]="repositories.length > 10">
        <ng-template #list let-items>
          <div class="grid grid-nogutter">
            <div class="col-12" *ngFor="let repo of items; let first = first">
              <div class="p-4 border-1 surface-border surface-card mb-3 border-round shadow-1">
                <div class="flex flex-column sm:flex-row sm:align-items-center gap-3">
                  <div class="flex-1">
                    <div class="flex align-items-center gap-2 mb-2">
                       <i class="pi pi-github text-xl"></i>
                       <span class="text-xl font-bold">{{ repo.name || repo.url }}</span>
                       <span class="text-secondary text-sm ml-2" *ngIf="repo.name">({{ repo.url }})</span>
                       <div class="ml-auto flex flex-column align-items-end">
                         <span class="text-secondary text-xs font-medium">Branche: <span class="text-primary">{{ repo.branch }}</span></span>
                         <span class="text-secondary text-xs font-medium" *ngIf="repo.subPath">Chemin: <span class="text-primary">{{ repo.subPath }}</span></span>
                       </div>
                    </div>

                    <div class="mt-4">
                      <div class="flex align-items-center gap-2 mb-3">
                         <i class="pi pi-history text-secondary"></i>
                         <span class="font-bold">Historique des scans</span>
                         <span class="text-sm text-secondary ml-auto mr-3" *ngIf="repo.scans?.length > 1">{{ repo.scans.length }} scans</span>
                          <p-button icon="pi pi-refresh" [rounded]="true" [text]="true" severity="secondary" size="small"
                                    pTooltip="Relancer le scan"
                                    *ngIf="canManage()"
                                    (onClick)="$event.stopPropagation(); rescan.emit({repoId: repo.id, branch: repo.branch, subPath: repo.subPath})">
                          </p-button>
                      </div>

                      <div class="scan-history border-1 surface-border border-round overflow-hidden">
                        <div class="flex flex-column">
                          <div *ngFor="let scan of repo.scans; let j = index"
                               class="scan-row flex justify-content-between align-items-center p-3 border-bottom-1 surface-border hover:surface-100 cursor-pointer transition-colors transition-duration-200"
                               [class.bg-blue-50]="j === 0"
                               [class.border-bottom-none]="j === repo.scans.length - 1"
                               (click)="viewDetails.emit({repo, scan})">
                            <div class="flex align-items-center gap-3">
                              <span class="text-sm font-medium text-secondary">{{ scan.createdAt | date:'dd/MM/yy HH:mm' }}</span>
                              <span *ngIf="j === 0" class="text-xs font-bold px-2 py-1 bg-primary-100 text-primary-700 border-round">DERNIER</span>
                              
                              <span class="status-badge" [ngClass]="'status-' + scan.status">
                                <i [class]="getStatusIcon(scan.status)"></i>
                                {{ getStatusLabel(scan.status) }}
                              </span>
                            </div>
                            <div class="flex align-items-center gap-3">
                              <ng-container *ngIf="scan.status === 'completed' && scan.summary">
                                <div class="flex gap-1">
                                  <p-tag [value]="scan.summary.critical.toString()" severity="danger" icon="pi pi-exclamation-triangle" *ngIf="scan.summary.critical > 0"></p-tag>
                                  <p-tag [value]="scan.summary.high.toString()" severity="warn" icon="pi pi-exclamation-circle" *ngIf="scan.summary.high > 0"></p-tag>
                                  <p-tag [value]="scan.summary.medium.toString()" severity="info" *ngIf="scan.summary.medium > 0"></p-tag>
                                </div>
                              </ng-container>
                              <span *ngIf="scan.status === 'failed'" class="text-xs text-red-500" [pTooltip]="scan.error || 'Erreur inconnue'" tooltipPosition="left">
                                <i class="pi pi-info-circle"></i>
                              </span>
                              <i class="pi pi-chevron-right text-secondary"></i>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </ng-template>
      </p-dataView>

      <div *ngIf="repositories.length === 0" class="flex flex-column align-items-center justify-content-center p-8 surface-card border-round border-1 border-dashed surface-border">
        <i class="pi pi-cloud-upload text-6xl text-secondary mb-4"></i>
        <h4 class="m-0 text-secondary">Aucun dépôt ajouté</h4>
        <p class="text-secondary mt-2">Connectez un nouveau dépôt pour démarrer une analyse de vulnérabilités.</p>
      </div>
    </div>
  `,
  styles: [`
    .scan-row { border-color: var(--surface-border); }
    .scan-row:last-child { border-bottom: none; }
    .scan-row:hover { background-color: var(--surface-hover); }

    /* Badges de statut */
    .status-badge {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 3px 10px;
      border-radius: 999px;
      font-size: 0.72rem;
      font-weight: 600;
      letter-spacing: 0.02em;
      white-space: nowrap;
    }
    .status-pending  { background: #f3f4f6; color: #6b7280; }
    .status-scanning { background: #dbeafe; color: #1d4ed8; }
    .status-completed{ background: #dcfce7; color: #15803d; }
    .status-failed   { background: #fee2e2; color: #b91c1c; }

    /* Spinner animation pour scanning */
    :host ::ng-deep .status-scanning .pi-spin {
      animation: spin 1s linear infinite;
    }
    @keyframes spin {
      from { transform: rotate(0deg); }
      to   { transform: rotate(360deg); }
    }
  `]
})
export class RepoListComponent {
  private auth = inject(AuthService);
  @Input() repositories: Repository[] = [];
  @Output() viewDetails = new EventEmitter<{repo: Repository, scan: Scan}>();
  @Output() rescan = new EventEmitter<{repoId: number, branch: string, subPath?: string}>();

  canManage(): boolean {
    const user = this.auth.user();
    return user?.role === 'admin' || user?.role === 'superuser';
  }


  getStatusLabel(status: string): string {
    switch (status) {
      case 'pending':   return 'En attente';
      case 'scanning':  return 'Démarré';
      case 'completed': return 'Terminé';
      case 'failed':    return 'Erreur';
      default:          return status;
    }
  }

  getStatusIcon(status: string): string {
    switch (status) {
      case 'pending':   return 'pi pi-clock';
      case 'scanning':  return 'pi pi-spin pi-spinner';
      case 'completed': return 'pi pi-check-circle';
      case 'failed':    return 'pi pi-times-circle';
      default:          return 'pi pi-circle';
    }
  }

  getStatusSeverity(status: string): 'success' | 'info' | 'warn' | 'danger' | 'secondary' | 'contrast' | undefined {
    switch (status) {
      case 'completed': return 'success';
      case 'scanning':  return 'info';
      case 'failed':    return 'danger';
      case 'pending':   return 'secondary';
      default:          return 'secondary';
    }
  }
}
