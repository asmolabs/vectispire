import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ApiService, Repository, Scan } from '../api';
import { DataViewModule } from 'primeng/dataview';
import { CardModule } from 'primeng/card';
import { TagModule } from 'primeng/tag';
import { ButtonModule } from 'primeng/button';
import { DialogModule } from 'primeng/dialog';
import { TableModule } from 'primeng/table';
import { TooltipModule } from 'primeng/tooltip';
import { InputTextModule } from 'primeng/inputtext';
import { FormsModule } from '@angular/forms';
import { RouterModule } from '@angular/router';
import { LimitToPipe } from '../shared/limit-to.pipe';
import { ScanDetailsComponent } from '../scan-details/scan-details';
import { SelectButtonModule } from 'primeng/selectbutton';
import { SelectModule } from 'primeng/select';
import { ToastModule } from 'primeng/toast';
import { ConfirmDialogModule } from 'primeng/confirmdialog';
import { MessageService, ConfirmationService } from 'primeng/api';

@Component({
  selector: 'app-depots',
  standalone: true,
  imports: [
    CommonModule, 
    DataViewModule, 
    CardModule, 
    TagModule, 
    ButtonModule, 
    DialogModule, 
    TableModule,
    TooltipModule,
    InputTextModule,
    FormsModule,
    RouterModule,
    LimitToPipe,
    ScanDetailsComponent,
    SelectButtonModule,
    SelectModule,
    ToastModule,
    ConfirmDialogModule
  ],
  providers: [MessageService, ConfirmationService],
  template: `
    <div class="depots-page">
      <!-- Header Section -->
      <div class="flex justify-content-between align-items-center mb-5">
        <div class="flex align-items-center gap-3">
          <p-button *ngIf="view === 'details'" icon="pi pi-arrow-left" [rounded]="true" [text]="true" (click)="goBack()" pTooltip="Retour à la liste"></p-button>
          <div>
            <h2 class="text-3xl font-bold m-0 text-900">{{ view === 'list' ? 'Dépôts' : (selectedRepo?.name || 'Détails du dépôt') }}</h2>
            <p class="text-secondary m-0 mt-1">{{ view === 'list' ? 'Gérez et explorez vos dépôts connectés' : 'Configuration et historique des scans' }}</p>
          </div>
        </div>
        <div class="flex gap-2" *ngIf="view === 'list'">
            <p-button icon="pi pi-refresh" [rounded]="true" [text]="true" (click)="fetchRepositories()" [loading]="loading" pTooltip="Actualiser"></p-button>
            <p-button label="Ajouter un dépôt" icon="pi pi-plus" [rounded]="true" routerLink="/add-repo"></p-button>
        </div>
        <div class="flex gap-2" *ngIf="view === 'details'">
            <p-button label="Configurer" icon="pi pi-cog" [outlined]="true" [rounded]="true" (click)="openConfig()"></p-button>
            <p-button label="Lancer un scan" icon="pi pi-play" [rounded]="true" (click)="triggerScan()"></p-button>
        </div>
      </div>

      <!-- Loading State -->
      <div *ngIf="loading" class="flex flex-column align-items-center justify-content-center p-8">
        <i class="pi pi-spin pi-spinner text-5xl text-primary mb-3"></i>
        <span class="text-secondary font-medium">Récupération des données...</span>
      </div>

      <!-- List View -->
      <div *ngIf="!loading && view === 'list'">
        <div class="card shadow-1 border-round p-0 surface-card overflow-hidden mt-4" *ngIf="repositories.length > 0">
          <div class="p-4 border-bottom-1 border-100 flex justify-content-between align-items-center bg-50">
            <div class="flex align-items-center">
              <i class="pi pi-list text-primary mr-2"></i>
              <span class="font-bold text-lg">Liste des dépôts ({{ repositories.length }})</span>
            </div>
            <span class="p-input-icon-left">
              <i class="pi pi-search"></i>
              <input pInputText type="text" (input)="dt.filterGlobal($any($event.target).value, 'contains')" placeholder="Rechercher..." class="p-inputtext-sm" />
            </span>
          </div>

          <p-table #dt [value]="repositories" [rows]="10" [paginator]="true" [rowsPerPageOptions]="[5, 10, 25, 50]"
                   [globalFilterFields]="['name','url','branch']"
                   responsiveLayout="scroll" styleClass="p-datatable-sm border-round"
                   [rowHover]="true" (onRowSelect)="showDetails($any($event).data)" selectionMode="single">
            <ng-template pTemplate="header">
              <tr>
                <th pSortableColumn="name" style="width: 25%">Dépôt <p-sortIcon field="name"></p-sortIcon></th>
                <th pSortableColumn="branch" style="width: 15%">Branche <p-sortIcon field="branch"></p-sortIcon></th>
                <th pSortableColumn="lastScan" style="width: 15%">Dernier Scan <p-sortIcon field="lastScan"></p-sortIcon></th>
                <th style="width: 10%">Version</th>
                <th class="text-center" style="width: 20%">Vulnérabilités</th>
                <th pSortableColumn="status" style="width: 15%">Statut <p-sortIcon field="status"></p-sortIcon></th>
              </tr>
            </ng-template>
            <ng-template pTemplate="body" let-repo>
              <tr [pSelectableRow]="repo" class="cursor-pointer">
                <td>
                  <div class="flex align-items-center gap-2">
                    <i class="pi pi-github text-xl text-500"></i>
                    <div class="flex flex-column">
                      <span class="font-bold text-900" *ngIf="repo.name">{{ repo.name }}</span>
                      <span [class]="repo.name ? 'text-xs text-secondary mt-1' : 'font-bold text-900'">{{ repo.url | limitTo:40 }}</span>
                    </div>
                  </div>
                </td>
                <td>
                  <span class="branch-chip">
                    <i class="pi pi-code text-xs"></i> {{ repo.branch }}
                  </span>
                </td>
                <td class="text-sm text-secondary">
                  {{ (getLatestScan(repo)?.createdAt | date:'dd/MM/yy HH:mm') || '—' }}
                </td>
                <td>
                  <p-tag [value]="getLatestScan(repo)?.version || '---'" severity="secondary" [rounded]="true" styleClass="text-xs"></p-tag>
                </td>
                <td class="text-center">
                  <div class="flex gap-1 justify-content-center">
                    <ng-container *ngIf="getLatestScan(repo) as scan">
                      <div class="flex align-items-center gap-1" *ngIf="scan.status === 'completed' && scan.summary; else scanStatus">
                         <ng-container *ngIf="scan.summary.total > 0; else ras">
                            <span class="vuln-chip critical" *ngIf="scan.summary.critical > 0" pTooltip="Critical">{{ scan.summary.critical }}</span>
                            <span class="vuln-chip high"     *ngIf="scan.summary.high > 0"     pTooltip="High">{{ scan.summary.high }}</span>
                            <span class="vuln-chip medium"   *ngIf="scan.summary.medium > 0"   pTooltip="Medium">{{ scan.summary.medium }}</span>
                            <span class="vuln-chip low"      *ngIf="scan.summary.low > 0"      pTooltip="Low">{{ scan.summary.low }}</span>
                         </ng-container>
                         <ng-template #ras><span class="text-xs text-green-600 font-semibold">✓ RAS</span></ng-template>
                      </div>
                      <ng-template #scanStatus>
                        <span class="text-xs text-secondary italic" *ngIf="scan.status !== 'failed'">En cours...</span>
                        <span class="text-xs text-red-500 font-bold" *ngIf="scan.status === 'failed'">Échec</span>
                      </ng-template>
                    </ng-container>
                    <span *ngIf="!getLatestScan(repo)" class="text-xs text-secondary italic">Aucun scan</span>
                  </div>
                </td>
                <td>
                   <div class="status-badge text-xs" [ngClass]="'status-' + (getLatestScan(repo)?.status || 'pending')">
                      <i [class]="getStatusIcon(getLatestScan(repo)?.status)"></i>
                      {{ getStatusLabel(getLatestScan(repo)?.status) }}
                   </div>
                </td>
              </tr>
            </ng-template>
            <ng-template pTemplate="emptymessage">
                <tr>
                    <td colspan="6" class="text-center p-5 text-secondary">
                        <i class="pi pi-search text-4xl block mb-3"></i>
                        Aucun dépôt trouvé correspondant à votre recherche.
                    </td>
                </tr>
            </ng-template>
          </p-table>
        </div>

        <!-- Empty State -->
        <div *ngIf="repositories.length === 0" class="flex flex-column align-items-center justify-content-center p-8 surface-card border-round border-1 border-dashed surface-border mt-4">
          <i class="pi pi-database text-6xl text-200 mb-4"></i>
          <h4 class="m-0 text-secondary">Aucun dépôt configuré</h4>
          <p class="text-secondary mt-2">Connectez votre premier dépôt pour lancer une analyse.</p>
          <p-button label="Connecter un dépôt" icon="pi pi-plus" class="mt-4" [outlined]="true" routerLink="/add-repo"></p-button>
        </div>
      </div>

      <!-- Details View -->
      <div *ngIf="!loading && view === 'details' && selectedRepo" class="fadein animation-duration-400">
        <div class="grid">
          <!-- Repo Specs Card -->
          <div class="col-12 lg:col-4">
            <div class="card shadow-1 border-round p-4 surface-card h-full">
              <h5 class="text-xl font-bold mb-4 border-bottom-1 border-100 pb-3 flex align-items-center gap-2">
                <i class="pi pi-info-circle text-primary"></i> Configuration
              </h5>
              <div class="flex flex-column gap-4">
                <div class="flex flex-column gap-1" *ngIf="selectedRepo.name">
                  <span class="text-xs font-bold text-500 uppercase">Nom du dépôt</span>
                  <div class="text-900 font-bold text-lg">
                    {{ selectedRepo.name }}
                  </div>
                </div>
                <div class="flex flex-column gap-1">
                  <span class="text-xs font-bold text-500 uppercase">URL du dépôt</span>
                  <div class="text-900 font-medium break-all bg-50 p-2 border-round border-1 border-100 text-sm">
                    {{ selectedRepo.url }}
                  </div>
                </div>
                <div class="grid nogutter">
                  <div class="col-6 pr-2">
                    <span class="text-xs font-bold text-500 uppercase">Branche</span>
                    <div class="text-900 font-bold mt-1 flex align-items-center gap-2">
                      <span class="branch-chip"><i class="pi pi-code text-primary"></i> {{ selectedRepo.branch }}</span>
                    </div>
                  </div>
                  <div class="col-6" *ngIf="selectedRepo.subPath">
                    <span class="text-xs font-bold text-500 uppercase">Chemin</span>
                    <div class="text-900 font-bold mt-1 flex align-items-center gap-2">
                      <i class="pi pi-folder text-primary"></i> {{ selectedRepo.subPath }}
                    </div>
                  </div>
                </div>
                <div class="flex flex-column gap-1 pt-2 border-top-1 border-100">
                  <span class="text-xs font-bold text-500 uppercase">Planification</span>
                  <div class="flex align-items-center gap-2 mt-1">
                    <p-tag [severity]="(selectedRepo.scanIntervalMinutes || selectedRepo.scanCron) ? 'success' : 'secondary'" 
                           [icon]="(selectedRepo.scanIntervalMinutes || selectedRepo.scanCron) ? 'pi pi-calendar' : 'pi pi-calendar-times'"
                           [value]="getScheduleLabel(selectedRepo)">
                    </p-tag>
                  </div>
                </div>
                <div class="mt-2 pt-4 border-top-1 border-100">
                  <p-button label="Lancer un scan" icon="pi pi-play" styleClass="w-full" (click)="triggerScan()"></p-button>
                </div>
              </div>
            </div>
          </div>

          <!-- History Table Card -->
          <div class="col-12 lg:col-8">
            <div class="card shadow-1 border-round p-0 surface-card overflow-hidden">
              <div class="p-4 border-bottom-1 border-100 flex justify-content-between align-items-center bg-50">
                <div class="flex align-items-center">
                  <i class="pi pi-history text-primary mr-2"></i>
                  <span class="font-bold text-lg">Historique des Scans</span>
                </div>
                <p-tag [value]="selectedRepo.scans.length + ' analyses'" severity="secondary" [rounded]="true"></p-tag>
              </div>
              
              <p-table [value]="selectedRepo.scans" [rows]="10" [paginator]="true" [rowsPerPageOptions]="[5, 10, 25, 50]"
                       responsiveLayout="scroll" styleClass="p-datatable-sm border-round" [rowHover]="true">
                <ng-template pTemplate="header">
                  <tr>
                    <th pSortableColumn="status" style="width: 15%">Statut <p-sortIcon field="status"></p-sortIcon></th>
                    <th style="width: 25%">Vulnérabilités</th>
                    <th pSortableColumn="createdAt" style="width: 20%">Date <p-sortIcon field="createdAt"></p-sortIcon></th>
                    <th pSortableColumn="version" style="width: 15%">Version <p-sortIcon field="version"></p-sortIcon></th>
                    <th pSortableColumn="durationMs" style="width: 15%">Durée <p-sortIcon field="durationMs"></p-sortIcon></th>
                    <th class="text-center" style="width: 10%">Action</th>
                  </tr>
                </ng-template>
                <ng-template pTemplate="body" let-scan>
                  <tr class="hover:surface-50 transition-colors">
                    <td>
                      <span class="status-badge text-xs" [ngClass]="'status-' + scan.status">
                        <i [class]="getStatusIcon(scan.status)"></i>
                        {{ getStatusLabel(scan.status) }}
                      </span>
                    </td>
                    <td>
                      <ng-container *ngIf="scan.status === 'completed' && scan.summary; else noVulns">
                        <div class="flex align-items-center gap-1" *ngIf="scan.summary.total > 0; else ras">
                          <span class="vuln-chip critical" *ngIf="scan.summary.critical > 0" pTooltip="Critical">{{ scan.summary.critical }}</span>
                          <span class="vuln-chip high"     *ngIf="scan.summary.high > 0"     pTooltip="High">{{ scan.summary.high }}</span>
                          <span class="vuln-chip medium"   *ngIf="scan.summary.medium > 0"   pTooltip="Medium">{{ scan.summary.medium }}</span>
                          <span class="vuln-chip low"      *ngIf="scan.summary.low > 0"      pTooltip="Low">{{ scan.summary.low }}</span>
                        </div>
                        <ng-template #ras>
                          <span class="text-xs text-green-600 font-semibold">✓ RAS</span>
                        </ng-template>
                      </ng-container>
                      <ng-template #noVulns>
                        <span class="text-xs text-secondary italic" *ngIf="scan.status !== 'failed'">Analyse en cours...</span>
                        <span class="text-xs text-red-500 font-bold" *ngIf="scan.status === 'failed'">Échec de l'analyse</span>
                      </ng-template>
                    </td>
                    <td class="text-sm font-medium text-secondary">
                      {{ scan.createdAt | date:'dd MMM yyyy, HH:mm' }}
                    </td>
                    <td>
                      <p-tag [value]="scan.version || '---'" severity="secondary" [rounded]="true" styleClass="text-xs"></p-tag>
                    </td>
                    <td class="text-sm text-secondary">
                      {{ scan.durationMs ? (scan.durationMs / 1000 | number:'1.0-0') + 's' : '—' }}
                    </td>
                    <td class="text-center">
                      <div class="flex gap-2 justify-content-center">
                        <p-button icon="pi pi-eye" [text]="true" size="small" severity="info"
                                  pTooltip="Voir les détails"
                                  (click)="showScanDetails(scan)">
                        </p-button>
                        <p-button icon="pi pi-refresh" [text]="true" size="small" severity="secondary"
                                  pTooltip="Relancer"
                                  [disabled]="scan.status === 'scanning' || scan.status === 'pending'"
                                  (click)="relancerScan(scan)">
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
                        <td colspan="6" class="text-center p-5 text-secondary">
                            Aucun scan effectué pour ce dépôt.
                        </td>
                    </tr>
                </ng-template>
              </p-table>
            </div>
          </div>
        </div>
      <!-- Scan Details Modal -->
      <app-scan-details 
        [(display)]="displayDetails" 
        [scan]="selectedScan" 
        [repo]="selectedRepo"
        (displayChange)="!$event && closeModal()">
      </app-scan-details>

      <!-- Configuration Modal -->
      <p-dialog header="Configuration de la planification" [(visible)]="displayConfig" [modal]="true" [style]="{width: '500px'}" [draggable]="false" [resizable]="false">
        <div class="p-fluid">
          <div class="field mb-4 flex justify-content-center">
            <p-selectButton [options]="modeOptions" [(ngModel)]="configMode" optionLabel="label" optionValue="value">
                <ng-template pTemplate="item" let-item>
                    <i [class]="item.icon" class="mr-2"></i>
                    <span>{{item.label}}</span>
                </ng-template>
            </p-selectButton>
          </div>

          <!-- Interval Mode -->
          <div *ngIf="configMode === 'interval'" class="fadein">
            <div class="field mb-4">
              <label class="font-bold block mb-2">Fréquence de scan</label>
              <div class="flex gap-2">
                <div class="flex-grow-1">
                  <input type="number" pInputText [(ngModel)]="configIntervalValue" placeholder="Valeur" min="0" class="w-full" />
                </div>
                <div style="width: 140px">
                  <p-select [options]="unitOptions" [(ngModel)]="configIntervalUnit" optionLabel="label" optionValue="value" class="w-full"></p-select>
                </div>
              </div>
              <small class="text-secondary mt-2 block">Exemple: Toutes les 2 heures.</small>
            </div>
          </div>

          <!-- Cron Mode -->
          <div *ngIf="configMode === 'cron'" class="fadein">
            <div class="field mb-4">
              <label for="cron" class="font-bold block mb-2">Expression Cron</label>
              <div class="p-inputgroup">
                <span class="p-inputgroup-addon"><i class="pi pi-code"></i></span>
                <input type="text" pInputText id="cron" [(ngModel)]="configCron" placeholder="* * * * *" />
              </div>
              <div class="mt-2 flex justify-content-between align-items-center">
                <small class="text-secondary">Standard: minute heure jour mois jour-semaine</small>
                <a href="https://crontab.guru" target="_blank" class="text-xs no-underline text-primary font-bold">
                  Aide (crontab.guru) <i class="pi pi-external-link text-xs"></i>
                </a>
              </div>
            </div>
          </div>

          <div class="p-3 bg-blue-50 border-round text-blue-700 text-sm mb-4">
             <i class="pi pi-info-circle mr-2"></i>
             Laissez vide ou mettez 0 pour désactiver le scan automatique.
          </div>
        </div>
        <ng-template pTemplate="footer">
          <p-button label="Annuler" icon="pi pi-times" [text]="true" (click)="displayConfig = false"></p-button>
          <p-button label="Enregistrer" icon="pi pi-check" (click)="saveConfig()"></p-button>
        </ng-template>
      </p-dialog>
      
      <p-toast></p-toast>
      <p-confirmDialog></p-confirmDialog>
    </div>
  `,
  styles: [`
    .depots-page { max-width: 1200px; margin: 0 auto; padding: 1rem; }
    .card-premium {
      background: var(--surface-card);
      border: 1px solid var(--surface-border);
      padding: 1.5rem;
      border-radius: 1rem;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
    }
    .status-badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 12px;
      border-radius: 999px;
      font-size: 0.72rem;
      font-weight: 700;
      text-transform: uppercase;
    }
    .status-pending  { background: #f1f5f9; color: #64748b; }
    .status-scanning { background: #e0f2fe; color: #0284c7; }
    .status-completed{ background: #f0fdf4; color: #16a34a; }
    .status-failed   { background: #fef2f2; color: #dc2626; }

    .branch-chip {
      display: inline-flex; align-items: center; gap: 4px;
      background: #f1f5f9; color: #475569;
      padding: 2px 8px; border-radius: 6px;
      font-size: 0.75rem; font-weight: 500;
    }

    .border-left-3 { border-left-width: 5px !important; }
    .border-status-completed { border-left-color: #10b981 !important; }
    .border-status-scanning  { border-left-color: #3b82f6 !important; }
    .border-status-failed    { border-left-color: #ef4444 !important; }
    .border-status-pending   { border-left-color: #94a3b8 !important; }

    .white-space-nowrap { white-space: nowrap; }
    .text-overflow-ellipsis { text-overflow: ellipsis; }

    @keyframes fadein {
        from { opacity: 0; transform: translateY(10px); }
        to { opacity: 1; transform: translateY(0); }
    }
    .fadein { animation: fadein 0.4s ease-out; }

    /* Vuln chips as seen in Scan Center */
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
export class DepotsComponent implements OnInit {
  private api = inject(ApiService);
  private msg = inject(MessageService);
  private confirmService = inject(ConfirmationService);
  
  repositories: Repository[] = [];
  selectedRepo: Repository | null = null;
  selectedScan: Scan | null = null;
  displayDetails = false;
  view: 'list' | 'details' = 'list';
  loading = true;

  displayConfig = false;
  configInterval: number | null = null; // Legacy field for saveConfig compatibility during transition
  configMode: 'interval' | 'cron' = 'interval';
  configIntervalValue: number | null = null;
  configIntervalUnit: 'min' | 'h' | 'd' = 'min';
  configCron: string = '';

  unitOptions = [
    { label: 'Minutes', value: 'min' },
    { label: 'Heures', value: 'h' },
    { label: 'Jours', value: 'd' }
  ];

  modeOptions = [
    { label: 'Intervalle', value: 'interval', icon: 'pi pi-clock' },
    { label: 'Cron (Expert)', value: 'cron', icon: 'pi pi-code' }
  ];

  ngOnInit() {
    this.fetchRepositories();
  }

  fetchRepositories() {
    this.loading = true;
    this.api.getRepositories().subscribe({
      next: (repos) => {
        this.repositories = repos;
        this.loading = false;
        // If we are in details, update the selected repo reference
        if (this.selectedRepo) {
          const updated = repos.find(r => r.id === this.selectedRepo?.id);
          if (updated) this.selectedRepo = updated;
        }
      },
      error: () => this.loading = false
    });
  }

  showScanDetails(scan: Scan) {
    this.selectedScan = scan;
    this.displayDetails = true;
  }

  closeModal() {
    this.displayDetails = false;
    this.selectedScan = null;
  }

  showDetails(repo: Repository) {
    this.selectedRepo = repo;
    this.view = 'details';
    window.scrollTo(0, 0);
  }

  goBack() {
    this.view = 'list';
    this.selectedRepo = null;
    window.scrollTo(0, 0);
  }

  openConfig() {
    if (!this.selectedRepo) return;
    
    if (this.selectedRepo.scanCron) {
      this.configMode = 'cron';
      this.configCron = this.selectedRepo.scanCron;
      this.configIntervalValue = null;
    } else {
      this.configMode = 'interval';
      const totalMin = this.selectedRepo.scanIntervalMinutes || 0;
      if (totalMin === 0) {
        this.configIntervalValue = null;
        this.configIntervalUnit = 'min';
      } else if (totalMin % 1440 === 0) {
        this.configIntervalValue = totalMin / 1440;
        this.configIntervalUnit = 'd';
      } else if (totalMin % 60 === 0) {
        this.configIntervalValue = totalMin / 60;
        this.configIntervalUnit = 'h';
      } else {
        this.configIntervalValue = totalMin;
        this.configIntervalUnit = 'min';
      }
      this.configCron = '';
    }
    this.displayConfig = true;
  }

  saveConfig() {
    if (!this.selectedRepo) return;
    
    let scanIntervalMinutes = 0;
    let scanCron: string | undefined = undefined;

    if (this.configMode === 'interval') {
      const val = this.configIntervalValue || 0;
      if (this.configIntervalUnit === 'd') scanIntervalMinutes = val * 1440;
      else if (this.configIntervalUnit === 'h') scanIntervalMinutes = val * 60;
      else scanIntervalMinutes = val;
      scanCron = undefined; // Clear cron if switching to interval
    } else {
      scanCron = this.configCron;
      scanIntervalMinutes = 0; // Clear interval if switching to cron
    }

    this.api.updateRepository(this.selectedRepo.id, { 
      scanIntervalMinutes,
      scanCron
    }).subscribe(() => {
      this.displayConfig = false;
      this.fetchRepositories();
    });
  }

  triggerScan() {
    if (!this.selectedRepo) return;
    this.api.triggerRescan(this.selectedRepo.id, this.selectedRepo.branch, this.selectedRepo.subPath).subscribe(() => {
      this.fetchRepositories();
      this.msg.add({ severity: 'success', summary: 'Scan lancé', detail: `Analyse démarrée sur "${this.selectedRepo?.branch}"` });
    });
  }

  relancerScan(scan: Scan) {
    if (!this.selectedRepo) return;
    this.api.triggerRescan(this.selectedRepo.id, scan.branch).subscribe({
      next: () => {
        this.msg.add({ severity: 'info', summary: 'Relancé', detail: `Scan relancé sur "${scan.branch}"` });
        this.fetchRepositories();
      },
      error: () => this.msg.add({ severity: 'error', summary: 'Erreur', detail: 'Impossible de relancer le scan' })
    });
  }

  deleteScan(scan: Scan) {
    if (!this.selectedRepo) return;
    this.confirmService.confirm({
      message: `Êtes-vous sûr de vouloir supprimer ce scan (${scan.branch}) ?`,
      header: 'Confirmation de suppression',
      icon: 'pi pi-exclamation-triangle',
      acceptLabel: 'Oui, supprimer',
      rejectLabel: 'Annuler',
      accept: () => {
        // selectedRepo will be definitely defined here due to the check above
        this.api.deleteScan(this.selectedRepo!.id, scan.id).subscribe({
          next: () => {
            this.msg.add({ severity: 'success', summary: 'Succès', detail: 'Scan supprimé' });
            this.fetchRepositories();
          },
          error: () => this.msg.add({ severity: 'error', summary: 'Erreur', detail: 'Impossible de supprimer le scan' })
        });
      }
    });
  }

  getLatestScan(repo: Repository): Scan | null {
    if (!repo.scans || repo.scans.length === 0) return null;
    return repo.scans[0];
  }

  getVulnerabilityTotal(repo: Repository): number {
    const scan = this.getLatestScan(repo);
    if (!scan || !scan.summary) return 0;
    return (scan.summary.critical || 0) + (scan.summary.high || 0) + (scan.summary.medium || 0);
  }

  getRiskColor(repo: Repository): string {
    const total = this.getVulnerabilityTotal(repo);
    if (total === 0) return 'text-green-500';
    if (total > 10) return 'text-red-500';
    return 'text-orange-500';
  }

  getStatusBarClass(repo: Repository): string {
    const status = this.getLatestScan(repo)?.status || 'pending';
    return 'border-status-' + status;
  }

  getStatusLabel(status: string | undefined): string {
    switch (status) {
      case 'pending':   return 'Attente';
      case 'scanning':  return 'Scan...';
      case 'completed': return 'Terminé';
      case 'failed':    return 'Échec';
      default:          return 'Aucun';
    }
  }

  getStatusIcon(status: string | undefined): string {
    switch (status) {
      case 'pending':   return 'pi pi-clock';
      case 'scanning':  return 'pi pi-spin pi-spinner';
      case 'completed': return 'pi pi-check-circle';
      case 'failed':    return 'pi pi-times-circle';
      default:          return 'pi pi-info-circle';
    }
  }

  getScheduleLabel(repo: Repository): string {
    if (repo.scanCron) return 'Cron: ' + repo.scanCron;
    if (!repo.scanIntervalMinutes) return 'Manuelle uniquement';
    
    const min = repo.scanIntervalMinutes;
    if (min >= 1440 && min % 1440 === 0) return `${min / 1440} jour(s)`;
    if (min >= 60 && min % 60 === 0) return `${min / 60} heure(s)`;
    return `${min} minute(s)`;
  }
}
