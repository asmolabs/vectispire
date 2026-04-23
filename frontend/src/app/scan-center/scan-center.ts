import { Component, OnInit, OnDestroy, inject, Pipe, PipeTransform } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiService, Repository, Scan } from '../api';
import { SocketService } from '../socket.service';
import { Subscription } from 'rxjs';
import { ButtonModule } from 'primeng/button';
import { InputTextModule } from 'primeng/inputtext';
import { TagModule } from 'primeng/tag';
import { TableModule } from 'primeng/table';
import { TooltipModule } from 'primeng/tooltip';
import { ToastModule } from 'primeng/toast';
import { MessageService, ConfirmationService } from 'primeng/api';
import { ConfirmDialogModule } from 'primeng/confirmdialog';
import { ScanDetailsComponent } from '../scan-details/scan-details';

@Pipe({ name: 'truncateUrl', standalone: true })
export class TruncateUrlPipe implements PipeTransform {
  transform(url: string): string {
    if (!url) return '';
    // Keep only the last part: «github.com/user/repo»
    try {
      const cleaned = url.replace(/^git@/, '').replace(':', '/');
      const parts = cleaned.replace(/\.git$/, '').split('/');
      return parts.slice(-3).join('/');
    } catch { return url; }
  }
}

interface FlatScan extends Scan {
  repoUrl: string;
  repoName?: string;
  repoId: number;
}

interface RepoRow {
  repo: Repository;
  branch: string;
  isLaunching: boolean;
}

@Component({
  selector: 'app-scan-center',
  standalone: true,
  imports: [
    CommonModule, FormsModule,
    ButtonModule, InputTextModule, TagModule,
    TableModule, TooltipModule, ToastModule,
    ConfirmDialogModule,
    TruncateUrlPipe,
    ScanDetailsComponent,
  ],
  providers: [MessageService, ConfirmationService],
  template: `
    <div class="scan-center p-4">

      <!-- Header -->
      <div class="flex align-items-center justify-content-between mb-5">
        <div>
          <h2 class="m-0 text-2xl font-bold">Centre de scan</h2>
          <p class="text-secondary mt-1 mb-0">Lancez des analyses et consultez l'historique par dépôt et branche</p>
        </div>
        <div class="flex align-items-center gap-2">
          <span class="status-dot" [class.online]="isOnline"></span>
          <span class="text-sm text-secondary">{{ isOnline ? 'Temps réel activé' : 'Connexion...' }}</span>
          <p-button icon="pi pi-refresh" [outlined]="true" size="small" pTooltip="Actualiser" (click)="fetchRepos()"></p-button>
        </div>
      </div>

      <!-- ═══════════════════════════════════════════════════════════ -->
      <!-- TABLEAU 1 : REPOS (lancement de scan)                      -->
      <!-- ═══════════════════════════════════════════════════════════ -->
      <div class="card-section mb-5">
        <div class="section-header mb-3 flex flex-column sm:flex-row justify-content-between align-items-start sm:align-items-center gap-3">
          <div class="flex align-items-center">
            <i class="pi pi-list text-primary mr-2"></i>
            <span class="font-bold text-lg">Dépôts ({{ repoRows.length }})</span>
          </div>
          <span class="p-input-icon-left w-full sm:w-auto">
            <i class="pi pi-search"></i>
            <input pInputText type="text" (input)="dtRepos.filterGlobal($any($event.target).value, 'contains')" placeholder="Rechercher..." class="w-full sm:w-auto" />
          </span>
        </div>

        <p-table #dtRepos [value]="repoRows" [loading]="loading" styleClass="p-datatable-sm border-round"
                 [rowHover]="true" responsiveLayout="scroll"
                 [paginator]="true" [rows]="10" [rowsPerPageOptions]="[5, 10, 25, 50]"
                 [globalFilterFields]="['repo.url', 'repo.name', 'branch']">
          <ng-template pTemplate="header">
            <tr>
              <th pSortableColumn="repo.id" style="width:3rem"># <p-sortIcon field="repo.id"></p-sortIcon></th>
              <th pSortableColumn="repo.url">Nom / URL du dépôt <p-sortIcon field="repo.url"></p-sortIcon></th>
              <th style="width:160px">Clé SSH</th>
              <th pSortableColumn="repo.branch" style="width:160px">Branche <p-sortIcon field="repo.branch"></p-sortIcon></th>
              <th style="width:180px">Actions</th>
            </tr>
          </ng-template>

          <ng-template pTemplate="body" let-row>
            <tr>
              <td class="text-secondary text-sm">{{ row.repo.id }}</td>
              <td>
                 <div class="flex align-items-center gap-2">
                  <i class="pi pi-github text-secondary"></i>
                  <div class="flex flex-column">
                    <span class="font-bold text-sm" *ngIf="row.repo.name">{{ row.repo.name }}</span>
                    <span class="text-secondary text-xs" [class.font-medium]="!row.repo.name" [pTooltip]="row.repo.url" tooltipPosition="top">
                      {{ row.repo.url | truncateUrl }}
                    </span>
                  </div>
                </div>
              </td>
              <td>
                <span *ngIf="row.repo.sshKeyId" class="ssh-chip">
                  <i class="pi pi-key text-xs"></i> SSH
                </span>
                <span *ngIf="!row.repo.sshKeyId" class="text-secondary text-xs">HTTPS</span>
              </td>
              <td>
                <span class="branch-chip">
                  <i class="pi pi-code text-xs"></i> {{ row.repo.branch }}
                </span>
              </td>
              <td>
                <div class="flex gap-2">
                  <p-button
                    label="Lancer"
                    icon="pi pi-play"
                    size="small"
                    [loading]="row.isLaunching"
                    [disabled]="isRepoScanning(row.repo)"
                    (click)="launchScan(row)">
                  </p-button>
                  <p-button
                    icon="pi pi-trash"
                    size="small"
                    severity="danger"
                    [outlined]="true"
                    pTooltip="Supprimer"
                    (click)="deleteRepo(row.repo)">
                  </p-button>
                </div>
              </td>
            </tr>
          </ng-template>

          <ng-template pTemplate="emptymessage">
            <tr>
              <td colspan="5" class="text-center p-5 text-secondary">
                <i class="pi pi-inbox text-4xl block mb-3"></i>
                Aucun dépôt. Ajoutez-en un via "Ajouter un dépôt".
              </td>
            </tr>
          </ng-template>
        </p-table>
      </div>

      <!-- ═══════════════════════════════════════════════════════════ -->
      <!-- TABLEAU 2 : SCANS (historique)                             -->
      <!-- ═══════════════════════════════════════════════════════════ -->
      <div class="card-section">
        <div class="section-header mb-3 flex flex-column sm:flex-row justify-content-between align-items-start sm:align-items-center gap-3">
          <div class="flex align-items-center">
            <i class="pi pi-history text-primary mr-2"></i>
            <span class="font-bold text-lg">Historique des scans ({{ flatScans.length }})</span>
          </div>
          <span class="p-input-icon-left w-full sm:w-auto">
            <i class="pi pi-search"></i>
            <input pInputText type="text" (input)="dtScans.filterGlobal($any($event.target).value, 'contains')" placeholder="Rechercher..." class="w-full sm:w-auto" />
          </span>
        </div>

        <p-table #dtScans [value]="flatScans" [loading]="loading" styleClass="p-datatable-sm border-round"
                 [rowHover]="true" responsiveLayout="scroll"
                 [paginator]="true" [rows]="10" [rowsPerPageOptions]="[5, 10, 25, 50]"
                 [globalFilterFields]="['repoUrl', 'repoName', 'branch', 'status']">
          <ng-template pTemplate="header">
            <tr>
              <th pSortableColumn="id" style="width:3rem"># <p-sortIcon field="id"></p-sortIcon></th>
              <th pSortableColumn="repoUrl">Dépôt (Nom/URL) <p-sortIcon field="repoUrl"></p-sortIcon></th>
              <th pSortableColumn="branch" style="width:140px">Branche <p-sortIcon field="branch"></p-sortIcon></th>
              <th pSortableColumn="status" style="width:130px">Statut <p-sortIcon field="status"></p-sortIcon></th>
              <th style="width:200px">Vulnérabilités</th>
              <th pSortableColumn="createdAt" style="width:160px">Date <p-sortIcon field="createdAt"></p-sortIcon></th>
              <th pSortableColumn="durationMs" style="width:100px">Durée <p-sortIcon field="durationMs"></p-sortIcon></th>
              <th style="width:110px">Actions</th>
            </tr>
          </ng-template>

          <ng-template pTemplate="body" let-scan>
            <tr>
              <td class="text-secondary text-sm">{{ scan.id }}</td>
              <td>
                 <div class="flex flex-column">
                  <span class="font-bold text-sm" *ngIf="scan.repoName">{{ scan.repoName }}</span>
                  <span class="text-secondary text-xs" [pTooltip]="scan.repoUrl">
                    {{ scan.repoUrl | truncateUrl }}
                  </span>
                </div>
              </td>
              <td>
                <span class="branch-chip">
                  <i class="pi pi-code text-xs"></i> {{ scan.branch }}
                </span>
              </td>
              <td>
                <span class="status-badge" [ngClass]="'status-' + scan.status">
                  <i [class]="getStatusIcon(scan.status)"></i>
                  {{ getStatusLabel(scan.status) }}
                </span>
              </td>
              <td>
                <ng-container *ngIf="scan.status === 'completed' && scan.summary">
                  <div class="flex align-items-center gap-1" *ngIf="scan.summary.total > 0; else noVulns">
                    <span class="vuln-chip critical" *ngIf="scan.summary.critical > 0" pTooltip="Critical">{{ scan.summary.critical }}</span>
                    <span class="vuln-chip high"     *ngIf="scan.summary.high > 0"     pTooltip="High">{{ scan.summary.high }}</span>
                    <span class="vuln-chip medium"   *ngIf="scan.summary.medium > 0"   pTooltip="Medium">{{ scan.summary.medium }}</span>
                    <span class="vuln-chip low"      *ngIf="scan.summary.low > 0"      pTooltip="Low">{{ scan.summary.low }}</span>
                    <span class="text-xs text-secondary ml-1">/ {{ scan.summary.total }}</span>
                  </div>
                  <ng-template #noVulns>
                    <span class="text-xs text-green-600 font-semibold">✓ Aucune</span>
                  </ng-template>
                </ng-container>
                <span *ngIf="scan.status === 'failed'" class="text-xs text-red-500">
                  <i class="pi pi-exclamation-triangle mr-1"></i>Échec
                </span>
                <span *ngIf="scan.status === 'scanning' || scan.status === 'pending'" class="text-xs text-secondary">
                  En cours...
                </span>
              </td>
              <td class="text-sm text-secondary">{{ scan.createdAt | date:'dd/MM/yy HH:mm' }}</td>
              <td class="text-sm text-secondary">
                {{ scan.durationMs ? (scan.durationMs / 1000 | number:'1.0-0') + 's' : '—' }}
              </td>
              <td>
                <div class="flex gap-2">
                  <p-button icon="pi pi-eye" [text]="true" size="small" severity="info"
                            pTooltip="Voir les détails"
                            (click)="viewDetails(scan)">
                  </p-button>
                  <p-button icon="pi pi-refresh" [text]="true" size="small" severity="secondary"
                            pTooltip="Relancer"
                            [disabled]="scan.status === 'scanning' || scan.status === 'pending'"
                            (click)="relancerScan(scan.repoId, scan.branch)">
                  </p-button>
                  <p-button icon="pi pi-trash" [text]="true" size="small" severity="danger"
                            pTooltip="Supprimer"
                            [disabled]="scan.status === 'scanning' || scan.status === 'pending'"
                            (click)="deleteScan(scan)">
                  </p-button>
                </div>
              </td>
            </tr>
          </ng-template>

          <ng-template pTemplate="emptymessage">
            <tr>
              <td colspan="8" class="text-center p-5 text-secondary">
                <i class="pi pi-search text-4xl block mb-3"></i>
                Aucun scan trouvé. Lancez une analyse depuis le tableau ci-dessus.
              </td>
            </tr>
          </ng-template>
        </p-table>
      </div>
    </div>

    <app-scan-details 
      [(display)]="displayDetails" 
      [repo]="selectedRepo" 
      [scan]="selectedScan"
      (displayChange)="!$event && closeModal()">
    </app-scan-details>

    <p-toast position="bottom-right"></p-toast>
    <p-confirmDialog [style]="{width: '450px'}" acceptButtonStyleClass="p-button-danger" rejectButtonStyleClass="p-button-text p-button-secondary"></p-confirmDialog>
  `,
  styles: [`
    .scan-center { max-width: 1100px; margin: 0 auto; }

    .card-section {
      background: var(--surface-card);
      border-radius: 12px;
      border: 1px solid var(--surface-border);
      box-shadow: 0 1px 6px rgba(0,0,0,0.06);
      padding: 1.25rem;
    }

    .section-header {
      display: flex;
      align-items: center;
      padding-bottom: 0.75rem;
      border-bottom: 1px solid var(--surface-border);
    }

    .status-dot {
      width: 10px; height: 10px; border-radius: 50%;
      background: #ef4444; display: inline-block;
    }
    .status-dot.online { background: #10b981; box-shadow: 0 0 8px #10b981; }

    /* Status badges */
    .status-badge {
      display: inline-flex; align-items: center; gap: 5px;
      padding: 3px 10px; border-radius: 999px;
      font-size: 0.72rem; font-weight: 600; white-space: nowrap;
    }
    .status-pending  { background: #f3f4f6; color: #6b7280; }
    .status-scanning { background: #dbeafe; color: #1d4ed8; }
    .status-completed{ background: #dcfce7; color: #15803d; }
    .status-failed   { background: #fee2e2; color: #b91c1c; }

    /* Branch chip */
    .branch-chip {
      display: inline-flex; align-items: center; gap: 4px;
      background: #f1f5f9; color: #475569;
      padding: 2px 8px; border-radius: 6px;
      font-size: 0.75rem; font-weight: 500;
    }

    /* SSH chip */
    .ssh-chip {
      display: inline-flex; align-items: center; gap: 4px;
      background: #faf5ff; color: #7c3aed;
      padding: 2px 8px; border-radius: 6px;
      font-size: 0.72rem; font-weight: 600;
    }

    /* Vuln chips */
    .vuln-chip {
      padding: 2px 8px; border-radius: 999px;
      font-size: 0.7rem; font-weight: 700; text-align: center;
    }
    .vuln-chip.critical { background: #fef2f2; color: #dc2626; }
    .vuln-chip.high     { background: #fff7ed; color: #ea580c; }
    .vuln-chip.medium   { background: #fefce8; color: #ca8a04; }
    .vuln-chip.low      { background: #eff6ff; color: #2563eb; }
  `]
})
export class ScanCenterComponent implements OnInit, OnDestroy {
  private api = inject(ApiService);
  private socket = inject(SocketService);
  private msg = inject(MessageService);
  private confirmService = inject(ConfirmationService);

  repoRows: RepoRow[] = [];
  flatScans: FlatScan[] = [];
  loading = true;
  isOnline = false;

  displayDetails = false;
  selectedRepo: Repository | null = null;
  selectedScan: Scan | null = null;

  private subs = new Subscription();

  ngOnInit() {
    this.fetchRepos();
    this.subs.add(this.socket.onScanUpdated().subscribe(() => this.fetchRepos()));
    this.subs.add(this.socket.onConnect().subscribe(() => this.isOnline = true));
    this.subs.add(this.socket.onDisconnect().subscribe(() => this.isOnline = false));
  }

  ngOnDestroy() { this.subs.unsubscribe(); }

  fetchRepos() {
    this.api.getRepositories().subscribe({
      next: (repos) => {
        // TABLE 1 — Un repo par ligne, branche conservée si déjà saisie
        this.repoRows = repos.map(repo => {
          return {
            repo,
            branch: repo.branch,
            isLaunching: false,
          };
        });

        // TABLE 2 — Tous les scans à plat (triés par date desc)
        const all: FlatScan[] = [];
        repos.forEach(repo => {
          (repo.scans ?? []).forEach(scan => {
            all.push({ ...scan, repoUrl: repo.url, repoName: repo.name, repoId: repo.id });
          });
        });
        all.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
        this.flatScans = all;

        this.loading = false;
      },
      error: () => {
        this.loading = false;
        this.msg.add({ severity: 'error', summary: 'Erreur', detail: 'Impossible de charger les dépôts' });
      }
    });
  }

  launchScan(row: RepoRow) {
    row.isLaunching = true;
    this.api.triggerRescan(row.repo.id, row.repo.branch).subscribe({
      next: () => {
        this.msg.add({ severity: 'success', summary: 'Scan lancé', detail: `Analyse démarrée sur "${row.repo.branch}"` });
        row.isLaunching = false;
        this.fetchRepos();
      },
      error: (err) => {
        row.isLaunching = false;
        this.msg.add({ severity: 'error', summary: 'Erreur', detail: err.error?.message || 'Impossible de lancer le scan' });
      }
    });
  }

  relancerScan(repoId: number, branch: string) {
    this.api.triggerRescan(repoId, branch).subscribe({
      next: () => {
        this.msg.add({ severity: 'info', summary: 'Relancé', detail: `Scan relancé sur "${branch}"` });
        this.fetchRepos();
      },
      error: () => this.msg.add({ severity: 'error', summary: 'Erreur', detail: 'Impossible de relancer le scan' })
    });
  }

  deleteRepo(repo: Repository) {
    this.confirmService.confirm({
      message: `Êtes-vous sûr de vouloir supprimer le dépôt <b>${repo.name || repo.url}</b> et tout son historique ?`,
      header: 'Confirmation de suppression',
      icon: 'pi pi-exclamation-triangle',
      acceptLabel: 'Oui, supprimer',
      rejectLabel: 'Annuler',
      accept: () => {
        this.api.deleteRepository(repo.id).subscribe({
          next: () => {
            this.msg.add({ severity: 'success', summary: 'Succès', detail: 'Dépôt supprimé avec succès' });
            this.fetchRepos();
          },
          error: () => this.msg.add({ severity: 'error', summary: 'Erreur', detail: 'Impossible de supprimer le dépôt' })
        });
      }
    });
  }

  deleteScan(scan: FlatScan) {
    this.confirmService.confirm({
      message: `Êtes-vous sûr de vouloir supprimer ce scan pour <b>${scan.repoName || scan.repoUrl}</b> (${scan.branch}) ?`,
      header: 'Confirmation de suppression',
      icon: 'pi pi-exclamation-triangle',
      acceptLabel: 'Oui, supprimer',
      rejectLabel: 'Annuler',
      accept: () => {
        this.api.deleteScan(scan.repoId, scan.id).subscribe({
          next: () => {
            this.msg.add({ severity: 'success', summary: 'Succès', detail: 'Scan supprimé avec succès' });
            this.fetchRepos();
          },
          error: () => this.msg.add({ severity: 'error', summary: 'Erreur', detail: 'Impossible de supprimer le scan' })
        });
      }
    });
  }

  viewDetails(flatScan: FlatScan) {
    const repoRow = this.repoRows.find(r => r.repo.id === flatScan.repoId);
    if (repoRow) {
      this.selectedRepo = repoRow.repo;
      this.selectedScan = flatScan;
      this.displayDetails = true;
    }
  }

  closeModal() {
    this.displayDetails = false;
    this.selectedRepo = null;
    this.selectedScan = null;
  }

  isRepoScanning(repo: Repository): boolean {
    return (repo.scans ?? []).some(s => s.status === 'scanning' || s.status === 'pending');
  }


  getStatusLabel(status: string): string {
    switch (status) {
      case 'pending':   return 'En attente';
      case 'scanning':  return 'En cours';
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
}
