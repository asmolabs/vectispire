import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ApiService, Container, Scan } from '../api';
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
import { ScanDetailsComponent } from '../scan-details/scan-details';
import { SelectButtonModule } from 'primeng/selectbutton';
import { SelectModule } from 'primeng/select';
import { ToastModule } from 'primeng/toast';
import { ConfirmDialogModule } from 'primeng/confirmdialog';
import { MessageService, ConfirmationService } from 'primeng/api';

@Component({
  selector: 'app-containers',
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
    ScanDetailsComponent,
    SelectButtonModule,
    SelectModule,
    ToastModule,
    ConfirmDialogModule
  ],
  providers: [MessageService, ConfirmationService],
  template: `
    <div class="depots-page">
      <p-toast></p-toast>
      <p-confirmDialog header="Confirmation" icon="pi pi-exclamation-triangle"></p-confirmDialog>

      <!-- Header Section -->
      <div class="flex justify-content-between align-items-center mb-5">
        <div class="flex align-items-center gap-3">
          <p-button *ngIf="view === 'details'" icon="pi pi-arrow-left" [rounded]="true" [text]="true" (click)="goBack()" pTooltip="Retour à la liste"></p-button>
          <div>
            <h2 class="text-3xl font-bold m-0 text-900">{{ view === 'list' ? 'Conteneurs Docker' : selectedContainer?.imageName }}</h2>
            <p class="text-secondary m-0 mt-1">{{ view === 'list' ? 'Gérez et explorez vos images Docker' : 'Configuration et historique des scans' }}</p>
          </div>
        </div>
        <div class="flex gap-2" *ngIf="view === 'list'">
            <p-button icon="pi pi-refresh" [rounded]="true" [text]="true" (click)="fetchContainers()" [loading]="loading" pTooltip="Actualiser"></p-button>
            <p-button label="Ajouter un conteneur" icon="pi pi-plus" [rounded]="true" routerLink="/add-container"></p-button>
        </div>
        <div class="flex gap-2" *ngIf="view === 'details'">
            <p-button label="Configurer" icon="pi pi-cog" [outlined]="true" [rounded]="true" (click)="openConfig()"></p-button>
            <p-button label="Lancer un scan" icon="pi pi-play" [rounded]="true" (click)="triggerScan()"></p-button>
            <p-button icon="pi pi-trash" severity="danger" [rounded]="true" [outlined]="true" (click)="confirmDeleteContainer()"></p-button>
        </div>
      </div>

      <!-- Loading State -->
      <div *ngIf="loading" class="flex flex-column align-items-center justify-content-center p-8">
        <i class="pi pi-spin pi-spinner text-5xl text-primary mb-3"></i>
        <span class="text-secondary font-medium">Récupération des données...</span>
      </div>

      <!-- List View -->
      <div *ngIf="!loading && view === 'list'">
        <div class="card shadow-1 border-round p-0 surface-card overflow-hidden mt-4" *ngIf="containers.length > 0">
          <div class="p-4 border-bottom-1 border-100 flex justify-content-between align-items-center bg-50">
            <div class="flex align-items-center">
              <i class="pi pi-box text-primary mr-2"></i>
              <span class="font-bold text-lg">Liste des conteneurs ({{ containers.length }})</span>
            </div>
            <span class="p-input-icon-left">
              <i class="pi pi-search"></i>
              <input pInputText type="text" (input)="dt.filterGlobal($any($event.target).value, 'contains')" placeholder="Rechercher..." class="p-inputtext-sm" />
            </span>
          </div>

          <p-table #dt [value]="containers" [rows]="10" [paginator]="true" [rowsPerPageOptions]="[5, 10, 25, 50]"
                   [globalFilterFields]="['imageName','registry','tag']"
                   responsiveLayout="scroll" styleClass="p-datatable-sm border-round"
                   [rowHover]="true" (onRowSelect)="showDetails($any($event).data)" selectionMode="single">
            <ng-template pTemplate="header">
              <tr>
                <th pSortableColumn="imageName" style="width: 25%">Image <p-sortIcon field="imageName"></p-sortIcon></th>
                <th pSortableColumn="tag" style="width: 15%">Tag <p-sortIcon field="tag"></p-sortIcon></th>
                <th pSortableColumn="lastScan" style="width: 15%">Dernier Scan <p-sortIcon field="lastScan"></p-sortIcon></th>
                <th class="text-center" style="width: 20%">Vulnérabilités</th>
                <th pSortableColumn="status" style="width: 15%">Statut <p-sortIcon field="status"></p-sortIcon></th>
              </tr>
            </ng-template>
            <ng-template pTemplate="body" let-container>
              <tr [pSelectableRow]="container" class="cursor-pointer">
                <td>
                  <div class="flex flex-column">
                    <span class="font-semibold text-900">{{ container.imageName }}</span>
                    <span class="text-sm text-500" *ngIf="container.registry">{{ container.registry }}</span>
                  </div>
                </td>
                <td>
                  <p-tag [value]="container.tag" severity="info" [rounded]="true"></p-tag>
                </td>
                <td>
                  <span class="text-sm text-600" *ngIf="container.scans?.length > 0">
                    {{ container.scans[container.scans.length - 1].createdAt | date:'dd/MM/yyyy HH:mm' }}
                  </span>
                  <span class="text-sm text-400 font-italic" *ngIf="!container.scans || container.scans.length === 0">Jamais</span>
                </td>
                <td class="text-center">
                  <div class="flex gap-2 justify-content-center" *ngIf="container.scans?.length > 0 && container.scans[container.scans.length - 1].status === 'completed'">
                    <p-tag *ngIf="container.scans[container.scans.length - 1].summary?.critical > 0" severity="danger" [value]="container.scans[container.scans.length - 1].summary.critical.toString()" pTooltip="Critique"></p-tag>
                    <p-tag *ngIf="container.scans[container.scans.length - 1].summary?.high > 0" severity="warn" [value]="container.scans[container.scans.length - 1].summary.high.toString()" pTooltip="Élevé"></p-tag>
                    <p-tag *ngIf="container.scans[container.scans.length - 1].summary?.medium > 0" severity="info" [value]="container.scans[container.scans.length - 1].summary.medium.toString()" pTooltip="Moyen"></p-tag>
                    <span *ngIf="(container.scans[container.scans.length - 1].summary?.critical || 0) === 0 && (container.scans[container.scans.length - 1].summary?.high || 0) === 0 && (container.scans[container.scans.length - 1].summary?.medium || 0) === 0" class="text-500 text-sm">
                      <i class="pi pi-check-circle text-green-500 mr-1"></i> Clean
                    </span>
                  </div>
                  <span class="text-sm text-400 font-italic" *ngIf="!container.scans || container.scans.length === 0 || container.scans[container.scans.length - 1].status !== 'completed'">N/A</span>
                </td>
                <td>
                  <p-tag *ngIf="!container.scans || container.scans.length === 0" value="Aucun scan" severity="secondary" [rounded]="true"></p-tag>
                  <p-tag *ngIf="container.scans?.length > 0 && container.scans[container.scans.length - 1].status === 'completed'" value="Terminé" severity="success" [rounded]="true"></p-tag>
                  <p-tag *ngIf="container.scans?.length > 0 && container.scans[container.scans.length - 1].status === 'failed'" value="Échec" severity="danger" [rounded]="true"></p-tag>
                  <p-tag *ngIf="container.scans?.length > 0 && container.scans[container.scans.length - 1].status === 'pending'" value="En attente" severity="warn" icon="pi pi-clock" [rounded]="true"></p-tag>
                  <p-tag *ngIf="container.scans?.length > 0 && container.scans[container.scans.length - 1].status === 'scanning'" value="En cours" severity="info" icon="pi pi-spin pi-spinner" [rounded]="true"></p-tag>
                </td>
              </tr>
            </ng-template>
            <ng-template pTemplate="emptymessage">
              <tr>
                <td colspan="5" class="text-center p-4">Aucun conteneur trouvé.</td>
              </tr>
            </ng-template>
          </p-table>
        </div>

        <!-- Empty State -->
        <div *ngIf="containers.length === 0" class="flex flex-column align-items-center justify-content-center p-8 text-center bg-white border-round shadow-1 mt-4">
          <div class="surface-100 border-circle p-4 mb-4">
            <i class="pi pi-box text-6xl text-primary"></i>
          </div>
          <h3 class="text-2xl font-bold text-900 mb-2">Aucun conteneur surveillé</h3>
          <p class="text-secondary max-w-20rem mb-4 line-height-3">Ajoutez votre première image Docker pour commencer à l'analyser et détecter les vulnérabilités.</p>
          <p-button label="Ajouter une image" icon="pi pi-plus" [rounded]="true" size="large" routerLink="/add-container"></p-button>
        </div>
      </div>

      <!-- Details View -->
      <div *ngIf="view === 'details' && selectedContainer" class="fadein animation-duration-400">
        <div class="grid">
          <!-- Container Specs Card -->
          <div class="col-12 lg:col-4">
            <div class="card shadow-1 border-round p-4 surface-card h-full">
              <h5 class="text-xl font-bold mb-4 border-bottom-1 border-100 pb-3 flex align-items-center gap-2">
                <i class="pi pi-info-circle text-primary"></i> Configuration
              </h5>
              <div class="flex flex-column gap-4">
                <div class="flex flex-column gap-1">
                  <span class="text-xs font-bold text-500 uppercase">Image</span>
                  <div class="text-900 font-bold text-lg">
                    {{ selectedContainer.imageName }}
                  </div>
                </div>
                <div class="flex flex-column gap-1" *ngIf="selectedContainer.registry">
                  <span class="text-xs font-bold text-500 uppercase">Registre</span>
                  <div class="text-900 font-medium break-all bg-50 p-2 border-round border-1 border-100 text-sm">
                    {{ selectedContainer.registry }}
                  </div>
                </div>
                <div class="grid nogutter">
                  <div class="col-12">
                    <span class="text-xs font-bold text-500 uppercase">Tag</span>
                    <div class="text-900 font-bold mt-1 flex align-items-center gap-2">
                      <p-tag [value]="selectedContainer.tag" severity="info" [rounded]="true"></p-tag>
                    </div>
                  </div>
                </div>
                <div class="flex flex-column gap-1 pt-2 border-top-1 border-100">
                  <span class="text-xs font-bold text-500 uppercase">Planification</span>
                  <div class="flex align-items-center gap-2 mt-1">
                    <p-tag [severity]="(selectedContainer.scanIntervalMinutes || selectedContainer.scanCron) ? 'success' : 'secondary'" 
                           [icon]="(selectedContainer.scanIntervalMinutes || selectedContainer.scanCron) ? 'pi pi-calendar' : 'pi pi-calendar-times'"
                           [value]="(selectedContainer.scanIntervalMinutes || selectedContainer.scanCron) ? 'Configurée' : 'Non planifié'">
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
                <p-tag [value]="(selectedContainer.scans?.length || 0) + ' analyses'" severity="secondary" [rounded]="true"></p-tag>
              </div>
              
              <p-table [value]="selectedContainer.scans" [rows]="10" [paginator]="true" [rowsPerPageOptions]="[5, 10, 25, 50]"
                       responsiveLayout="scroll" styleClass="p-datatable-sm border-round" [rowHover]="true" [sortOrder]="-1" sortField="createdAt">
                <ng-template pTemplate="header">
                  <tr>
                    <th pSortableColumn="status" style="width: 15%">Statut <p-sortIcon field="status"></p-sortIcon></th>
                    <th style="width: 30%">Vulnérabilités</th>
                    <th pSortableColumn="createdAt" style="width: 25%">Date <p-sortIcon field="createdAt"></p-sortIcon></th>
                    <th pSortableColumn="durationMs" style="width: 15%">Durée <p-sortIcon field="durationMs"></p-sortIcon></th>
                    <th class="text-center" style="width: 15%">Action</th>
                  </tr>
                </ng-template>
                <ng-template pTemplate="body" let-scan>
                  <tr class="hover:surface-50 transition-colors">
                    <td>
                      <p-tag *ngIf="scan.status === 'completed'" value="Terminé" severity="success" [rounded]="true"></p-tag>
                      <p-tag *ngIf="scan.status === 'failed'" value="Échec" severity="danger" [rounded]="true"></p-tag>
                      <p-tag *ngIf="scan.status === 'pending'" value="En attente" severity="warn" icon="pi pi-clock" [rounded]="true"></p-tag>
                      <p-tag *ngIf="scan.status === 'scanning'" value="En cours" severity="info" icon="pi pi-spin pi-spinner" [rounded]="true"></p-tag>
                    </td>
                    <td>
                      <div class="flex gap-1" *ngIf="scan.status === 'completed' && scan.summary">
                         <p-tag *ngIf="scan.summary.critical > 0" severity="danger" [value]="scan.summary.critical.toString()" pTooltip="Critique"></p-tag>
                         <p-tag *ngIf="scan.summary.high > 0" severity="warn" [value]="scan.summary.high.toString()" pTooltip="Élevé"></p-tag>
                         <p-tag *ngIf="scan.summary.medium > 0" severity="info" [value]="scan.summary.medium.toString()" pTooltip="Moyen"></p-tag>
                         <span *ngIf="scan.summary.critical === 0 && scan.summary.high === 0 && scan.summary.medium === 0" class="text-500 text-sm"><i class="pi pi-check text-green-500"></i> Clean</span>
                      </div>
                      <span *ngIf="scan.status !== 'completed'" class="text-500 font-italic">N/A</span>
                    </td>
                    <td class="text-600 text-sm font-medium">
                      {{ scan.createdAt | date:'dd/MM/yyyy HH:mm' }}
                    </td>
                    <td class="text-600 text-sm">
                      <span *ngIf="scan.durationMs">{{ (scan.durationMs / 1000 | number:'1.0-1') }}s</span>
                      <span *ngIf="!scan.durationMs" class="text-400 font-italic">N/A</span>
                    </td>
                    <td>
                      <div class="flex justify-content-center gap-2">
                        <p-button *ngIf="scan.status === 'completed'" icon="pi pi-eye" [text]="true" [rounded]="true" (click)="viewScanDetails(scan)" pTooltip="Voir les détails" size="small"></p-button>
                        <p-button *ngIf="scan.status === 'failed'" icon="pi pi-refresh" [text]="true" [rounded]="true" severity="warn" (click)="relancerScan(scan)" pTooltip="Relancer" size="small"></p-button>
                        <p-button icon="pi pi-trash" [text]="true" [rounded]="true" severity="danger" (click)="confirmDeleteScan(scan)" pTooltip="Supprimer" size="small"></p-button>
                      </div>
                    </td>
                  </tr>
                </ng-template>
                <ng-template pTemplate="emptymessage">
                  <tr>
                    <td colspan="5" class="text-center p-5 text-secondary">
                      <i class="pi pi-info-circle text-4xl block mb-3"></i>
                      Aucun scan dans l'historique de cette image.
                    </td>
                  </tr>
                </ng-template>
              </p-table>
            </div>
          </div>
        </div>
      </div>
    </div>

    <app-scan-details 
      [(display)]="showScanDetails" 
      [scan]="selectedScanForDetails"
      (displayChange)="!$event && closeScanDetails()">
    </app-scan-details>

    <!-- Configuration Dialog -->
    <p-dialog [(visible)]="displayConfig" [modal]="true" header="Configuration du conteneur" [style]="{width: '35rem'}">
      <div class="flex flex-column gap-4 pt-3" *ngIf="selectedContainer">
        
        <div class="flex flex-column gap-2">
          <label class="font-semibold">Mode de planification</label>
          <p-selectButton [options]="scheduleModes" [(ngModel)]="selectedScheduleMode" optionLabel="label" optionValue="value" (onChange)="onScheduleModeChange()"></p-selectButton>
        </div>

        <div class="flex flex-column gap-2" *ngIf="selectedScheduleMode === 'interval'">
          <label class="font-semibold">Intervalle (minutes)</label>
          <div class="p-inputgroup">
            <input pInputText type="number" [(ngModel)]="configInterval" placeholder="Ex: 1440 (24h)" min="0" />
            <span class="p-inputgroup-addon">min</span>
          </div>
          <small class="text-500">Mettez 0 ou laissez vide pour désactiver la planification par intervalle.</small>
        </div>

        <div class="flex flex-column gap-2" *ngIf="selectedScheduleMode === 'cron'">
          <label class="font-semibold">Expression Cron</label>
          <input pInputText [(ngModel)]="configCron" placeholder="Ex: 0 0 * * *" />
          <small class="text-500">Format: minute heure jour mois jour-semaine. Laissez vide pour désactiver.</small>
          <small class="text-primary font-medium mt-1"><i class="pi pi-info-circle mr-1"></i>Ex: "0 2 * * *" (tous les jours à 2h00)</small>
        </div>
        
        <div *ngIf="configError" class="text-red-500 text-sm mt-2">
          {{ configError }}
        </div>
      </div>
      <ng-template pTemplate="footer">
        <p-button label="Annuler" icon="pi pi-times" [outlined]="true" severity="secondary" (click)="displayConfig = false"></p-button>
        <p-button label="Sauvegarder" icon="pi pi-check" (click)="saveConfig()"></p-button>
      </ng-template>
    </p-dialog>
  `
})
export class ContainersComponent implements OnInit {
  containers: Container[] = [];
  loading = false;
  view: 'list' | 'details' = 'list';
  selectedContainer: Container | null = null;
  activeTab: 'history' = 'history';

  // Details Dialog
  showScanDetails = false;
  selectedScanForDetails: Scan | null = null;

  // Config Dialog
  displayConfig = false;
  configInterval: number | null = null;
  configCron: string | null = null;
  configError = '';
  
  scheduleModes = [
    { label: 'Intervalle', value: 'interval' },
    { label: 'Cron', value: 'cron' }
  ];
  selectedScheduleMode: 'interval' | 'cron' = 'interval';

  private apiService = inject(ApiService);
  private messageService = inject(MessageService);
  private confirmationService = inject(ConfirmationService);

  ngOnInit() {
    this.fetchContainers();
  }

  fetchContainers() {
    this.loading = true;
    this.apiService.getContainers().subscribe({
      next: (data) => {
        this.containers = data;
        this.loading = false;
        
        // Update selected container if we are in details view
        if (this.view === 'details' && this.selectedContainer) {
          this.selectedContainer = this.containers.find(c => c.id === this.selectedContainer!.id) || null;
          if (!this.selectedContainer) {
            this.goBack();
          } else {
             this.selectedContainer.scans.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
          }
        }
      },
      error: (err) => {
        this.loading = false;
        this.messageService.add({severity:'error', summary: 'Erreur', detail: 'Impossible de récupérer les conteneurs'});
      }
    });
  }

  showDetails(container: Container) {
    this.selectedContainer = container;
    if (this.selectedContainer.scans) {
      this.selectedContainer.scans.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
    }
    this.view = 'details';
    this.activeTab = 'history';
  }

  goBack() {
    this.view = 'list';
    this.selectedContainer = null;
  }

  triggerScan() {
    if (!this.selectedContainer) return;
    this.apiService.triggerContainerScan(this.selectedContainer.id).subscribe({
      next: () => {
        this.messageService.add({severity:'success', summary: 'Scan lancé', detail: "Le scan a été ajouté à la file d'attente"});
        this.fetchContainers(); // Refresh to see the new pending scan
      },
      error: () => {
        this.messageService.add({severity:'error', summary: 'Erreur', detail: 'Impossible de lancer le scan'});
      }
    });
  }

  relancerScan(scan: Scan) {
    this.triggerScan(); // For containers, branch/subPath is irrelevant, we just re-trigger it.
  }

  viewScanDetails(scan: Scan) {
    this.selectedScanForDetails = scan;
    this.showScanDetails = true;
  }

  closeScanDetails() {
    this.showScanDetails = false;
    this.selectedScanForDetails = null;
  }

  confirmDeleteScan(scan: Scan) {
    if (!this.selectedContainer) return;
    this.confirmationService.confirm({
      message: 'Voulez-vous vraiment supprimer cet historique de scan ?',
      header: 'Confirmation de suppression',
      icon: 'pi pi-exclamation-triangle',
      acceptLabel: 'Oui',
      rejectLabel: 'Non',
      acceptButtonStyleClass: 'p-button-danger',
      accept: () => {
        this.apiService.deleteContainerScan(this.selectedContainer!.id, scan.id).subscribe({
          next: () => {
            this.messageService.add({severity:'success', summary: 'Succès', detail: 'Scan supprimé'});
            this.fetchContainers();
          },
          error: () => this.messageService.add({severity:'error', summary: 'Erreur', detail: 'Impossible de supprimer le scan'})
        });
      }
    });
  }

  confirmDeleteContainer() {
    if (!this.selectedContainer) return;
    this.confirmationService.confirm({
      message: 'Voulez-vous vraiment supprimer ce conteneur et tout son historique ?',
      header: 'Confirmation de suppression',
      icon: 'pi pi-exclamation-triangle',
      acceptLabel: 'Oui',
      rejectLabel: 'Non',
      acceptButtonStyleClass: 'p-button-danger',
      accept: () => {
        this.apiService.deleteContainer(this.selectedContainer!.id).subscribe({
          next: () => {
            this.messageService.add({severity:'success', summary: 'Succès', detail: 'Conteneur supprimé'});
            this.goBack();
            this.fetchContainers();
          },
          error: () => this.messageService.add({severity:'error', summary: 'Erreur', detail: 'Impossible de supprimer le conteneur'})
        });
      }
    });
  }

  openConfig() {
    if (!this.selectedContainer) return;
    
    // Default to interval mode if nothing is set or if interval is set
    this.selectedScheduleMode = this.selectedContainer.scanCron ? 'cron' : 'interval';
    this.configInterval = this.selectedContainer.scanIntervalMinutes || null;
    this.configCron = this.selectedContainer.scanCron || null;
    this.configError = '';
    this.displayConfig = true;
  }

  onScheduleModeChange() {
    this.configError = '';
  }

  saveConfig() {
    if (!this.selectedContainer) return;
    this.configError = '';

    const data: any = {
      scanIntervalMinutes: null,
      scanCron: null
    };

    if (this.selectedScheduleMode === 'interval') {
      if (this.configInterval !== null && this.configInterval < 0) {
        this.configError = 'L\'intervalle doit être positif';
        return;
      }
      data.scanIntervalMinutes = this.configInterval;
    } else {
      if (this.configCron && this.configCron.trim().split(' ').length < 5) {
        this.configError = 'Expression Cron invalide. Format attendu: * * * * *';
        return;
      }
      data.scanCron = this.configCron ? this.configCron.trim() : null;
    }

    this.apiService.updateContainer(this.selectedContainer.id, data).subscribe({
      next: () => {
        this.displayConfig = false;
        this.messageService.add({severity:'success', summary: 'Succès', detail: 'Configuration mise à jour'});
        this.fetchContainers();
      },
      error: () => {
        this.configError = 'Erreur lors de la sauvegarde';
      }
    });
  }
}
