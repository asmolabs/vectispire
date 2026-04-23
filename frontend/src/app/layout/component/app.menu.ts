import { Component, OnInit, inject, effect } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { AppMenuitem } from './app.menuitem';
import { AuthService } from '../../auth/auth.service';

@Component({
  selector: 'app-menu',
  standalone: true,
  imports: [CommonModule, RouterModule, AppMenuitem],
  template: `
    <ul class="layout-menu">
      <ng-container *ngFor="let item of model; let i = index">
        <li app-menuitem *ngIf="!item.separator" [item]="item" [index]="i" [root]="true"></li>
        <li *ngIf="item.separator" class="menu-separator"></li>
      </ng-container>
    </ul>
  `
})
export class AppMenu implements OnInit {
  authService = inject(AuthService);
  model: any[] = [];

  constructor() {
    // Re-update menu when user state changes
    effect(() => {
      this.authService.user();
      this.updateMenu();
    });
  }

  ngOnInit() {
    this.updateMenu();
  }

  updateMenu() {
    const user = this.authService.user();

    this.model = [
      {
        label: 'Home',
        items: [
          { label: 'Dashboard', icon: 'pi pi-fw pi-home', routerLink: ['/'] }
        ]
      },
      {
        label: 'Security',
        items: [
          { label: 'Dépôts', icon: 'pi pi-fw pi-database', routerLink: ['/depots'] },
          { label: 'Conteneurs', icon: 'pi pi-fw pi-box', routerLink: ['/containers'] }
        ]
      }


    ];

    if (user?.role === 'superuser') {
      this.model.push({
        label: 'Administration',
        items: [
          { label: 'Utilisateurs', icon: 'pi pi-fw pi-users', routerLink: ['/users'] },
          { label: 'Clés SSH', icon: 'pi pi-fw pi-key', routerLink: ['/ssh-keys'] },
          { label: 'API', icon: 'pi pi-fw pi-key', routerLink: ['/api-keys'] },
          { label: 'Paramètres', icon: 'pi pi-fw pi-shield', routerLink: ['/admin/settings'] },
        ]
      });
    }
  }
}
