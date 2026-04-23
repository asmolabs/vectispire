import { Component, Output, EventEmitter, inject, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiService, Repository, SSHKey } from '../api';
import { InputTextModule } from 'primeng/inputtext';
import { ButtonModule } from 'primeng/button';
import { MessageModule } from 'primeng/message';
import { SelectModule } from 'primeng/select';
import { RouterModule } from '@angular/router';

@Component({
  selector: 'app-add-repo',
  standalone: true,
  imports: [CommonModule, FormsModule, InputTextModule, ButtonModule, MessageModule, SelectModule, RouterModule],
  template: `
    <div class="card shadow-1 border-round p-4 surface-card mb-4">
      <h2 class="text-2xl font-bold mb-2">Git Security Scanner</h2>
      <p class="text-secondary mb-4">Analyze Git repositories with Syft (SBOM) and Grype (CVEs)</p>
      
      <div class="add-repo-form p-fluid mx-auto" style="max-width: 1000px;">
        <div class="grid align-items-end">
          <div class="col-12 md:col-3">
            <label for="repoName" class="block font-bold mb-2 text-sm text-secondary">Nom du dépôt (Optionnel)</label>
            <div class="p-inputgroup">
              <span class="p-inputgroup-addon"><i class="pi pi-tag"></i></span>
              <input pInputText id="repoName" type="text" [(ngModel)]="repoName" placeholder="Ex: Mon Projet" class="w-full" />
            </div>
          </div>
          <div class="col-12 md:col-6">
            <label for="repoUrl" class="block font-bold mb-2 text-sm text-secondary">URL du dépôt</label>
            <div class="p-inputgroup">
              <span class="p-inputgroup-addon"><i class="pi pi-link"></i></span>
              <input pInputText id="repoUrl" type="text" [(ngModel)]="repoUrl" placeholder="https://github.com/user/repo.git" class="w-full" />
            </div>
          </div>
          <div class="col-12 md:col-3">
            <label for="branch" class="block font-bold mb-2 text-sm text-secondary">Branche</label>
            <input pInputText id="branch" type="text" [(ngModel)]="branch" placeholder="main" class="w-full" />
          </div>
          <div class="col-12 md:col-6 mt-3">
            <label for="subPath" class="block font-bold mb-2 text-sm text-secondary">Chemin d'analyse (Optionnel)</label>
            <div class="p-inputgroup">
              <span class="p-inputgroup-addon"><i class="pi pi-folder"></i></span>
              <input pInputText id="subPath" type="text" [(ngModel)]="subPath" placeholder="Ex: backend/src" class="w-full" />
            </div>
            <small class="text-secondary">Laissez vide pour scanner tout le dépôt.</small>
          </div>
          <div class="col-12 md:col-6 mt-3">
            <label for="sshKey" class="block font-bold mb-2 text-sm text-secondary">Clé SSH (Optionnel)</label>
            <p-select [options]="sshKeys" [(ngModel)]="selectedSshKeyId" optionLabel="name" optionValue="id" placeholder="Sélectionnez une clé SSH" [showClear]="true" class="w-full"></p-select>
            <div class="mt-1">
              <a routerLink="/ssh-keys" class="text-xs text-primary no-underline hover:underline"><i class="pi pi-cog mr-1"></i>Gérer les clés SSH</a>
            </div>
          </div>
          <div class="col-12 md:col-3 mt-3">
            <p-button label="Ajouter & Scanner" icon="pi pi-plus" [loading]="isLoading" [disabled]="!repoUrl" (onClick)="onSubmit()" styleClass="p-button-raised w-full"></p-button>
          </div>
          <div class="col-12">
              <small class="text-secondary ml-1">Supporte les URLs HTTPS et SSH. Par défaut 'main' si vide.</small>
          </div>
          <div class="col-12 mt-2" *ngIf="errorMessage">
            <p-message severity="error" [text]="errorMessage" class="w-full"></p-message>
          </div>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .add-repo-form { margin-top: 1rem; }
  `]
})
export class AddRepoComponent implements OnInit {
  repoUrl = '';
  repoName = '';
  branch = 'main';
  subPath = '';
  sshKeys: SSHKey[] = [];
  selectedSshKeyId?: string;
  isLoading = false;
  errorMessage = '';
  private api = inject(ApiService);
  @Output() repoAdded = new EventEmitter<Repository>();

  ngOnInit() {
    this.api.getSSHKeys().subscribe({
      next: (keys) => this.sshKeys = keys,
      error: (err) => console.error('Failed to fetch SSH keys', err)
    });
  }

  onSubmit() {
    if (!this.repoUrl) return;
    this.isLoading = true;
    this.errorMessage = '';
    this.api.addRepository(this.repoUrl, this.branch, this.selectedSshKeyId, this.repoName, this.subPath).subscribe({
      next: (repo) => {
        this.repoAdded.emit(repo);
        this.repoUrl = '';
        this.repoName = '';
        this.branch = 'main';
        this.subPath = '';
        this.selectedSshKeyId = undefined;
        this.isLoading = false;
      },
      error: (err) => {
        console.error(err);
        this.errorMessage = err.error?.message || 'Failed to add repository. Please check for a valid URL.';
        this.isLoading = false;
      }
    });
  }
}
