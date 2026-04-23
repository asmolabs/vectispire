import { Component, inject, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ApiService } from '../api';
import { User, AuthService } from '../auth/auth.service';
import { TableModule } from 'primeng/table';
import { TagModule } from 'primeng/tag';
import { ButtonModule } from 'primeng/button';
import { SelectModule } from 'primeng/select';
import { FormsModule } from '@angular/forms';
import { MessageModule } from 'primeng/message';
import { InputTextModule } from 'primeng/inputtext';
import { TooltipModule } from 'primeng/tooltip';

@Component({
  selector: 'app-users',
  standalone: true,
  imports: [
    CommonModule, 
    TableModule, 
    TagModule, 
    ButtonModule, 
    SelectModule, 
    FormsModule, 
    MessageModule, 
    InputTextModule, 
    TooltipModule
  ],
  template: `
    <div class="card shadow-1 border-round p-4 surface-card">
      <div class="flex justify-content-between align-items-center mb-4">
        <div>
          <h2 class="text-2xl font-bold m-0">Gestion des utilisateurs</h2>
          <p class="text-secondary mt-1">Administrez les rôles et l'accès des membres de l'équipe</p>
        </div>
        <div class="flex align-items-center gap-3">
          <p-tag severity="info" value="Accès SuperUser" icon="pi pi-shield"></p-tag>
          <span class="p-input-icon-left">
            <i class="pi pi-search"></i>
            <input pInputText type="text" (input)="dt.filterGlobal($any($event.target).value, 'contains')" placeholder="Rechercher..." class="p-inputtext-sm" />
          </span>
        </div>
      </div>

      <p-table #dt [value]="users" [rows]="10" [paginator]="true" [rowsPerPageOptions]="[5, 10, 25, 50]"
               [globalFilterFields]="['username', 'displayName', 'email', 'role']"
               responsiveLayout="scroll" styleClass="p-datatable-sm border-round" [rowHover]="true">
        <ng-template pTemplate="header">
          <tr>
            <th pSortableColumn="username">Utilisateur <p-sortIcon field="username"></p-sortIcon></th>
            <th pSortableColumn="email">Email <p-sortIcon field="email"></p-sortIcon></th>
            <th pSortableColumn="role" style="width: 15%">Rôle actuel <p-sortIcon field="role"></p-sortIcon></th>
            <th pSortableColumn="isActive" style="width: 12%">État <p-sortIcon field="isActive"></p-sortIcon></th>
            <th style="width: 25%">Change Role / Action</th>
          </tr>
        </ng-template>
        <ng-template pTemplate="body" let-user>
          <tr>
            <td>
              <div class="flex align-items-center gap-2">
                <img [src]="user.avatarUrl" *ngIf="user.avatarUrl" class="border-circle" style="width: 32px">
                <div class="flex flex-column">
                  <span class="font-bold text-900">{{ user.displayName || user.username }}</span>
                  <span class="text-xs text-secondary" *ngIf="user.displayName">{{ user.username }}</span>
                </div>
              </div>
            </td>
            <td><span class="text-secondary text-sm">{{ user.email }}</span></td>
            <td>
              <span class="text-xs font-bold px-2 py-1 border-round uppercase" 
                    [ngClass]="getRoleClass(user.role)">
                {{ user.role }}
              </span>
            </td>
            <td>
              <p-tag [severity]="user.isActive ? 'success' : 'danger'" 
                     [value]="user.isActive ? 'Actif' : 'Inactif'"
                     [rounded]="true"
                     styleClass="text-xs">
              </p-tag>
            </td>
            <td>
              <div class="flex align-items-center gap-2">
                <p-select [options]="roleOptions" [(ngModel)]="user.pendingRole" 
                         optionLabel="label" optionValue="value" 
                         placeholder="Rôle" [disabled]="user.id === currentUserId"
                         class="w-full" styleClass="p-inputtext-sm">
                </p-select>
                <p-button icon="pi pi-check" size="small" [text]="true"
                         pTooltip="Appliquer le rôle"
                         [disabled]="!user.pendingRole || user.pendingRole === user.role || user.id === currentUserId"
                         (onClick)="updateRole(user)">
                </p-button>
                <p-button [icon]="user.isActive ? 'pi pi-user-minus' : 'pi pi-user-plus'" 
                         size="small" [text]="true"
                         [severity]="user.isActive ? 'danger' : 'success'"
                         [pTooltip]="user.isActive ? 'Suspendre' : 'Activer'"
                         [disabled]="user.id === currentUserId"
                         (onClick)="toggleActive(user)">
                </p-button>
              </div>
            </td>
          </tr>
        </ng-template>
        <ng-template pTemplate="emptymessage">
          <tr>
            <td colspan="5" class="text-center p-5 text-secondary">
              <i class="pi pi-users text-4xl block mb-3"></i>
              Aucun utilisateur trouvé.
            </td>
          </tr>
        </ng-template>
      </p-table>

      <div class="mt-4 p-3 bg-blue-50 border-round border-left-3 border-blue-500">
        <p class="m-0 text-blue-700 text-sm">
          <i class="pi pi-info-circle mr-2"></i>
          En tant que SuperUser, vous pouvez promouvoir d'autres utilisateurs. Vous ne pouvez pas modifier votre propre rôle.
        </p>
      </div>
    </div>
  `,
  styles: [`
    .border-left-3 { border-left-width: 4px !important; }
  `]
})
export class UsersComponent implements OnInit {
  private api = inject(ApiService);
  private auth = inject(AuthService);
  
  users: (User & { pendingRole?: string })[] = [];
  currentUserId: number | null = null;
  
  roleOptions = [
    { label: 'SuperUser', value: 'superuser' },
    { label: 'Administrateur', value: 'admin' },
    { label: 'Utilisateur', value: 'user' }
  ];

  ngOnInit() {
    this.currentUserId = this.auth.user()?.id || null;
    this.loadUsers();
  }

  loadUsers() {
    this.api.getUsers().subscribe(users => {
      this.users = users.map(u => ({ ...u, pendingRole: u.role }));
    });
  }

  updateRole(user: any) {
    this.api.updateUserRole(user.id, user.pendingRole).subscribe(() => {
      this.loadUsers();
    });
  }

  toggleActive(user: any) {
    this.api.updateUserStatus(user.id, !user.isActive).subscribe(() => {
      this.loadUsers();
    });
  }

  getRoleClass(role: string): string {
    switch (role) {
      case 'superuser': return 'bg-purple-100 text-purple-700';
      case 'admin':     return 'bg-blue-100 text-blue-700';
      case 'user':      return 'bg-gray-100 text-gray-700';
      default:          return 'bg-gray-100 text-gray-700';
    }
  }
}

