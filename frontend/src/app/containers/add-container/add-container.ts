import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { ApiService } from '../../api';
import { CardModule } from 'primeng/card';
import { InputTextModule } from 'primeng/inputtext';
import { ButtonModule } from 'primeng/button';
import { MessageModule } from 'primeng/message';

@Component({
  selector: 'app-add-container',
  standalone: true,
  imports: [CommonModule, FormsModule, CardModule, InputTextModule, ButtonModule, MessageModule],
  template: `
    <div class="flex justify-content-center align-items-center h-full pt-6">
      <p-card header="Ajouter une image Docker" subheader="Configurez une image Docker à scanner avec Syft et Grype" class="w-full max-w-30rem shadow-2">
        
        <div *ngIf="error" class="mb-4">
          <p-message severity="error" [text]="error" styleClass="w-full"></p-message>
        </div>

        <div class="flex flex-column gap-4">
          <div class="flex flex-column gap-2">
            <label for="registry" class="font-semibold text-900">Registre (Optionnel)</label>
            <input pInputText id="registry" [(ngModel)]="registry" placeholder="ex: docker.io (laisser vide pour défaut)" />
            <small class="text-500">L'URL du registre si ce n'est pas Docker Hub.</small>
          </div>

          <div class="flex flex-column gap-2">
            <label for="imageName" class="font-semibold text-900">Nom de l'image <span class="text-red-500">*</span></label>
            <input pInputText id="imageName" [(ngModel)]="imageName" placeholder="ex: nginx, alpine, mon-app" />
          </div>

          <div class="flex flex-column gap-2">
            <label for="tag" class="font-semibold text-900">Tag <span class="text-red-500">*</span></label>
            <input pInputText id="tag" [(ngModel)]="tag" placeholder="ex: latest, 1.2.3" />
          </div>
        </div>

        <ng-template pTemplate="footer">
          <div class="flex justify-content-end gap-3 mt-4">
            <p-button label="Annuler" icon="pi pi-times" [outlined]="true" severity="secondary" (click)="cancel()"></p-button>
            <p-button label="Ajouter" icon="pi pi-check" (click)="addContainer()" [loading]="loading" [disabled]="!imageName || !tag"></p-button>
          </div>
        </ng-template>
      </p-card>
    </div>
  `
})
export class AddContainerComponent {
  registry = '';
  imageName = '';
  tag = 'latest';
  loading = false;
  error = '';

  private apiService = inject(ApiService);
  private router = inject(Router);

  addContainer() {
    if (!this.imageName || !this.tag) {
      this.error = 'Le nom de l\'image et le tag sont requis';
      return;
    }

    this.loading = true;
    this.error = '';

    const reg = this.registry.trim() || undefined;

    this.apiService.addContainer(this.imageName.trim(), this.tag.trim(), reg).subscribe({
      next: () => {
        this.loading = false;
        this.router.navigate(['/containers']);
      },
      error: (err) => {
        this.loading = false;
        this.error = err.error?.message || 'Erreur lors de l\'ajout de l\'image';
      }
    });
  }

  cancel() {
    this.router.navigate(['/containers']);
  }
}
