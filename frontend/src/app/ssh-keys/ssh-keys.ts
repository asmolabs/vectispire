import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiService, SSHKey } from '../api';
import { TableModule } from 'primeng/table';
import { ButtonModule } from 'primeng/button';
import { DialogModule } from 'primeng/dialog';
import { InputTextModule } from 'primeng/inputtext';
import { TextareaModule } from 'primeng/textarea';
import { MessageService } from 'primeng/api';
import { ToastModule } from 'primeng/toast';
import { TooltipModule } from 'primeng/tooltip';
import { TagModule } from 'primeng/tag';

@Component({
  selector: 'app-ssh-keys',
  standalone: true,
  imports: [
    CommonModule, 
    FormsModule, 
    TableModule, 
    ButtonModule, 
    DialogModule, 
    InputTextModule, 
    TextareaModule,
    ToastModule,
    TooltipModule,
    TagModule
  ],
  providers: [MessageService],
  template: `
    <div class="card shadow-1 border-round p-4 surface-card">
      <div class="flex flex-column sm:flex-row justify-content-between align-items-start sm:align-items-center mb-4 gap-3">
        <div>
          <h2 class="text-2xl font-bold m-0 text-900">Clés SSH</h2>
          <p class="text-secondary mt-1">Gérez les clés de déploiement pour accéder aux dépôts privés</p>
        </div>
        <div class="flex align-items-center gap-3 w-full sm:w-auto">
          <span class="p-input-icon-left w-full sm:w-auto">
            <i class="pi pi-search"></i>
            <input pInputText type="text" (input)="dt.filterGlobal($any($event.target).value, 'contains')" placeholder="Rechercher..." class="w-full sm:w-auto p-inputtext-sm" />
          </span>
          <p-button label="Ajouter" icon="pi pi-plus" (onClick)="showDialog()" size="small"></p-button>
        </div>
      </div>

      <p-table #dt [value]="keys" [rows]="10" [paginator]="true" [rowsPerPageOptions]="[5, 10, 25, 50]"
               [globalFilterFields]="['name', 'id', 'publicKey']"
               responsiveLayout="scroll" styleClass="p-datatable-sm border-round" [rowHover]="true">
        <ng-template pTemplate="header">
          <tr>
            <th pSortableColumn="name">Nom <p-sortIcon field="name"></p-sortIcon></th>
            <th pSortableColumn="id" style="width: 25%">ID / Référence <p-sortIcon field="id"></p-sortIcon></th>
            <th>Clé Publique (GitHub/GitLab)</th>
            <th pSortableColumn="createdAt" style="width: 15%">Créée le <p-sortIcon field="createdAt"></p-sortIcon></th>
            <th class="text-center" style="width: 100px">Actions</th>
          </tr>
        </ng-template>
        <ng-template pTemplate="body" let-key>
          <tr class="hover:surface-50 transition-colors">
            <td>
              <div class="flex align-items-center gap-2">
                <i class="pi pi-key text-primary"></i>
                <span class="font-bold text-900">{{key.name}}</span>
              </div>
            </td>
            <td>
              <div class="flex align-items-center gap-2">
                <code class="text-xs surface-100 p-1 border-round text-blue-700 border-1 border-200">{{key.id}}</code>
                <p-button icon="pi pi-copy" size="small" [text]="true" (onClick)="copyToClipboard(key.id)" pTooltip="Copier l'ID"></p-button>
              </div>
            </td>
            <td>
              <div class="flex align-items-center gap-2" *ngIf="key.publicKey">
                <code class="text-xs surface-100 p-1 border-round text-600 border-1 border-200 block text-overflow-ellipsis overflow-hidden white-space-nowrap" style="max-width: 150px">
                  {{key.publicKey}}
                </code>
                <p-button icon="pi pi-copy" size="small" [text]="true" (onClick)="copyToClipboard(key.publicKey)" pTooltip="Copier la clé publique"></p-button>
              </div>
              <span *ngIf="!key.publicKey" class="text-400 italic text-xs">Indisponible</span>
            </td>
            <td class="text-sm text-secondary">{{key.createdAt | date:'dd/MM/yyyy HH:mm'}}</td>
            <td class="text-center">
              <p-button icon="pi pi-trash" severity="danger" [text]="true" size="small" (onClick)="confirmDelete(key)" pTooltip="Supprimer"></p-button>
            </td>
          </tr>
        </ng-template>
        <ng-template pTemplate="emptymessage">
          <tr>
            <td colspan="5" class="text-center p-5 text-secondary">
              <i class="pi pi-shield text-4xl block mb-3"></i>
              Aucune clé SSH trouvée.
            </td>
          </tr>
        </ng-template>
      </p-table>
    </div>

    <!-- Add Key Dialog -->
    <p-dialog [(visible)]="displayDialog" [header]="'Ajouter une clé SSH'" [modal]="true" [style]="{width: '500px'}" [draggable]="false" [resizable]="false" styleClass="border-round-xl">
      <div class="p-fluid">
        <div class="field mb-3">
          <label for="name" class="font-bold block mb-2 text-900">Nom de la clé</label>
          <input pInputText id="name" type="text" [(ngModel)]="newKey.name" placeholder="e.g., Jenkins Production" />
        </div>
        <div class="field mb-3">
          <label for="uuid" class="font-bold block mb-2 text-900">ID / Référence API <span class="text-400 font-normal">(Optionnel)</span></label>
          <div class="p-inputgroup">
            <span class="p-inputgroup-addon"><i class="pi pi-id-card"></i></span>
            <input pInputText id="uuid" type="text" [(ngModel)]="newKey.id" placeholder="Ex: custom-jenkins-id" />
          </div>
          <small class="text-secondary">Utile pour référencer cette clé dans vos automates.</small>
        </div>
        <div class="field mb-3">
          <div class="flex justify-content-between align-items-center mb-2">
            <label for="privateKey" class="font-bold text-900 m-0">Clé Privée <span class="text-400 font-normal text-xs">(format PEM)</span></label>
            <p-button label="Générer" icon="pi pi-refresh" size="small" [text]="true" (onClick)="generateKey()" [loading]="isGenerating"></p-button>
          </div>
          <textarea pTextarea id="privateKey" [(ngModel)]="newKey.privateKey" rows="8" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----..." class="text-xs"></textarea>
          <small class="text-secondary">Chiffrée sur le serveur. La clé publique sera extraite.</small>
        </div>
        <div class="field mb-0" *ngIf="generatedPublicKey">
          <div class="surface-100 p-3 border-round border-1 border-300 flex flex-column gap-2">
            <div class="flex align-items-center justify-content-between">
              <span class="text-xs font-bold text-success"><i class="pi pi-info-circle mr-1"></i>Clé Publique Générée</span>
              <p-button icon="pi pi-copy" [text]="true" size="small" (onClick)="copyToClipboard(generatedPublicKey)" pTooltip="Copier"></p-button>
            </div>
            <code class="text-xs break-all block surface-0 p-2 border-round border-1 border-100" style="max-height: 80px; overflow-y: auto;">{{generatedPublicKey}}</code>
          </div>
        </div>
      </div>
      <ng-template pTemplate="footer">
        <p-button label="Annuler" icon="pi pi-times" [text]="true" severity="secondary" (onClick)="hideDialog()"></p-button>
        <p-button label="Enregistrer" icon="pi pi-check" [disabled]="!newKey.name || !newKey.privateKey" (onClick)="saveKey()" [loading]="isSubmitting"></p-button>
      </ng-template>
    </p-dialog>

    <p-toast position="bottom-right"></p-toast>
  `
})
export class SSHKeyManagementComponent implements OnInit {
  keys: SSHKey[] = [];
  displayDialog = false;
  isSubmitting = false;
  isGenerating = false;
  newKey = { id: '', name: '', privateKey: '' };
  generatedPublicKey = '';
  
  private api = inject(ApiService);
  private messageService = inject(MessageService);

  ngOnInit() {
    this.fetchKeys();
  }

  fetchKeys() {
    this.api.getSSHKeys().subscribe({
      next: (keys) => this.keys = keys,
      error: (err) => {
        console.error(err);
        this.messageService.add({ severity: 'error', summary: 'Erreur', detail: 'Impossible de charger les clés SSH' });
      }
    });
  }

  showDialog() {
    this.newKey = { id: '', name: '', privateKey: '' };
    this.generatedPublicKey = '';
    this.displayDialog = true;
  }

  hideDialog() {
    this.displayDialog = false;
    this.generatedPublicKey = '';
  }

  generateKey() {
    this.isGenerating = true;
    this.api.generateSSHKey().subscribe({
      next: (resp) => {
        this.newKey.id = (resp as any).id;
        this.newKey.privateKey = resp.privateKey;
        this.generatedPublicKey = resp.publicKey;
        this.isGenerating = false;
        if (!this.newKey.name) {
          this.newKey.name = 'Clé générée le ' + new Date().toLocaleDateString();
        }
        this.messageService.add({ severity: 'info', summary: 'Générée', detail: 'Clés créées avec succès' });
      },
      error: (err) => {
        console.error(err);
        this.messageService.add({ severity: 'error', summary: 'Erreur', detail: 'Échec de la génération' });
        this.isGenerating = false;
      }
    });
  }

  copyToClipboard(text: string) {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text).then(() => {
        this.messageService.add({ severity: 'info', summary: 'Copié', detail: 'Copié dans le presse-papier' });
      });
    }
  }

  saveKey() {
    this.isSubmitting = true;
    const body: any = { 
      name: this.newKey.name, 
      privateKey: this.newKey.privateKey 
    };
    if (this.newKey.id) {
      body.id = this.newKey.id;
    }

    this.api.addSSHKey(body.name, body.privateKey, undefined, body.id).subscribe({
      next: () => {
        this.messageService.add({ severity: 'success', summary: 'Succès', detail: 'Clé enregistrée' });
        this.fetchKeys();
        this.hideDialog();
        this.isSubmitting = false;
      },
      error: (err) => {
        console.error(err);
        this.messageService.add({ severity: 'error', summary: 'Erreur', detail: err.error?.message || 'Échec de l\'ajout' });
        this.isSubmitting = false;
      }
    });
  }

  confirmDelete(key: SSHKey) {
    if (confirm(`Voulez-vous vraiment supprimer la clé "${key.name}" ?`)) {
      this.api.deleteSSHKey(key.id).subscribe({
        next: () => {
          this.messageService.add({ severity: 'success', summary: 'Succès', detail: 'Clé supprimée' });
          this.fetchKeys();
        },
        error: (err) => {
          console.error(err);
          this.messageService.add({ severity: 'error', summary: 'Erreur', detail: 'Échec de la suppression' });
        }
      });
    }
  }
}

