import { Component, inject, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ApiService, ApiKey } from '../api';
import { TableModule } from 'primeng/table';
import { ButtonModule } from 'primeng/button';
import { DialogModule } from 'primeng/dialog';
import { InputTextModule } from 'primeng/inputtext';
import { FormsModule } from '@angular/forms';
import { MessageModule } from 'primeng/message';
import { TagModule } from 'primeng/tag';
import { TooltipModule } from 'primeng/tooltip';
import { ToastModule } from 'primeng/toast';
import { MessageService } from 'primeng/api';

@Component({
  selector: 'app-api-keys',
  standalone: true,
  imports: [
    CommonModule, 
    TableModule, 
    ButtonModule, 
    DialogModule, 
    InputTextModule, 
    FormsModule, 
    MessageModule,
    TagModule,
    TooltipModule,
    ToastModule
  ],
  providers: [MessageService],

  template: `
    <div class="card shadow-1 border-round p-4 surface-card">
      <p-toast position="bottom-right"></p-toast>
      
      <div class="flex flex-column sm:flex-row justify-content-between align-items-start sm:align-items-center mb-4 gap-3">
        <div>
          <h2 class="text-2xl font-bold m-0 text-900">Clés d'API</h2>
          <p class="text-secondary mt-1">Gérez vos clés d'accès pour les déclenchements de scan externes</p>
        </div>
        <div class="flex align-items-center gap-3 w-full sm:w-auto">
          <span class="p-input-icon-left w-full sm:w-auto">
            <i class="pi pi-search"></i>
            <input pInputText type="text" (input)="dt.filterGlobal($any($event.target).value, 'contains')" placeholder="Rechercher..." class="w-full sm:w-auto p-inputtext-sm" />
          </span>
          <p-button label="Générer" icon="pi pi-plus" (onClick)="showCreateDialog()" size="small"></p-button>
        </div>
      </div>

      <p-table #dt [value]="apiKeys" [rows]="10" [paginator]="true" [rowsPerPageOptions]="[5, 10, 25, 50]"
               [globalFilterFields]="['name']"
               responsiveLayout="scroll" styleClass="p-datatable-sm border-round" [rowHover]="true">
        <ng-template pTemplate="header">
          <tr>
            <th pSortableColumn="name">Nom <p-sortIcon field="name"></p-sortIcon></th>
            <th pSortableColumn="lastUsedAt" style="width: 25%">Dernière utilisation <p-sortIcon field="lastUsedAt"></p-sortIcon></th>
            <th pSortableColumn="createdAt" style="width: 25%">Date de création <p-sortIcon field="createdAt"></p-sortIcon></th>
            <th class="text-center" style="width: 100px">Actions</th>
          </tr>
        </ng-template>
        <ng-template pTemplate="body" let-key>
          <tr class="hover:surface-50 transition-colors">
            <td>
              <div class="flex align-items-center gap-2">
                <i class="pi pi-shield text-primary"></i>
                <span class="font-bold text-900">{{ key.name }}</span>
              </div>
            </td>
            <td>
              <p-tag [value]="(key.lastUsedAt | date:'dd/MM/yyyy HH:mm') || 'Jamais utilisée'" 
                     [severity]="key.lastUsedAt ? 'success' : 'secondary'"
                     [rounded]="true"
                     styleClass="text-xs">
              </p-tag>
            </td>
            <td class="text-sm text-secondary">{{ key.createdAt | date:'dd/MM/yyyy HH:mm' }}</td>
            <td class="text-center">
              <p-button icon="pi pi-trash" size="small" severity="danger" [text]="true" 
                       (onClick)="deleteKey(key.id)" pTooltip="Supprimer la clé"></p-button>
            </td>
          </tr>
        </ng-template>
        <ng-template pTemplate="emptymessage">
          <tr>
            <td colspan="4" class="text-center p-5 text-secondary">
              <i class="pi pi-key text-4xl block mb-3"></i>
              Aucune clé d'API trouvée.
            </td>
          </tr>
        </ng-template>
      </p-table>

      <!-- Create Key Dialog -->
      <p-dialog header="Générer une nouvelle clé d'API" [(visible)]="createDialogVisible" 
                [modal]="true" [style]="{ width: '450px' }" [draggable]="false" [resizable]="false"
                styleClass="border-round-xl">
        <div class="p-fluid pt-2">
          <p class="text-secondary mb-4">Donnez un nom descriptif à votre clé (ex: Jenkins CI, GitHub Action).</p>
          <div class="field mb-4">
            <label for="keyName" class="font-bold text-900 block mb-2">Nom de la clé</label>
            <input pInputText id="keyName" [(ngModel)]="newKeyName" placeholder="Mon projet CI" />
          </div>
          <div class="flex justify-content-end gap-2">
            <p-button label="Annuler" severity="secondary" [text]="true" (onClick)="createDialogVisible = false"></p-button>
            <p-button label="Générer" icon="pi pi-check" (onClick)="createKey()" [disabled]="!newKeyName"></p-button>
          </div>
        </div>
      </p-dialog>

      <!-- Raw Key Display Dialog (Shown once) -->
      <p-dialog header="Clé d'API générée" [(visible)]="rawKeyDialogVisible" 
                [modal]="true" [style]="{ width: '450px' }" [closable]="false"
                styleClass="border-round-xl">
        <div class="pt-2">
          <div class="p-3 bg-orange-50 text-orange-700 border-round mb-4 text-sm font-bold flex align-items-center gap-2">
            <i class="pi pi-exclamation-triangle"></i>
            Attention : Cette clé ne sera affichée qu'une seule fois.
          </div>
          
          <div class="surface-100 p-3 border-round border-1 border-300 flex align-items-center justify-content-between mb-4">
            <code class="text-lg font-bold text-primary select-all overflow-hidden text-overflow-ellipsis">
              {{ generatedRawKey }}
            </code>
            <p-button icon="pi pi-copy" [text]="true" (onClick)="copyToClipboard(generatedRawKey)" pTooltip="Copier"></p-button>
          </div>

          <div class="flex justify-content-end">
            <p-button label="J'ai copié la clé" icon="pi pi-check" (onClick)="rawKeyDialogVisible = false" severity="success"></p-button>
          </div>
        </div>
      </p-dialog>
    </div>
  `,
  styles: [`
    .select-all { user-select: all; }
  `]
})
export class ApiKeyManagementComponent implements OnInit {
  private api = inject(ApiService);
  private messageService = inject(MessageService);
  
  apiKeys: ApiKey[] = [];
  createDialogVisible = false;
  rawKeyDialogVisible = false;
  newKeyName = '';
  generatedRawKey = '';

  ngOnInit() {
    this.reloadKeys();
  }

  reloadKeys() {
    this.api.getApiKeys().subscribe({
      next: (keys) => {
        this.apiKeys = keys;
      },
      error: (err) => {
        this.messageService.add({ severity: 'error', summary: 'Erreur', detail: 'Impossible de charger les clés d\'API' });
      }
    });
  }

  showCreateDialog() {
    this.newKeyName = '';
    this.createDialogVisible = true;
  }

  createKey() {
    if (!this.newKeyName) return;

    this.api.createApiKey(this.newKeyName).subscribe({
      next: (response) => {
        this.generatedRawKey = response.rawKey;
        this.createDialogVisible = false;
        this.rawKeyDialogVisible = true;
        this.reloadKeys();
        this.messageService.add({ severity: 'success', summary: 'Succès', detail: 'Clé d\'API générée' });
      },
      error: (err) => {
        this.messageService.add({ severity: 'error', summary: 'Erreur', detail: 'Échec de la génération de la clé' });
      }
    });
  }

  deleteKey(id: string) {
    if (confirm('Êtes-vous sûr de vouloir supprimer cette clé d\'API ?')) {
      this.api.deleteApiKey(id).subscribe({
        next: () => {
          this.messageService.add({ severity: 'success', summary: 'Supprimée', detail: 'La clé d\'API a été supprimée' });
          this.reloadKeys();
        },
        error: (err) => {
          this.messageService.add({ severity: 'error', summary: 'Erreur', detail: 'Impossible de supprimer la clé' });
        }
      });
    }
  }

  copyToClipboard(text: string) {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text).then(() => {
        // Success
      });
    }
  }
}

