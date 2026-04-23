import { Component, ElementRef, ViewChild, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { LayoutService } from '../service/layout.service';
import { AuthService } from '../../auth/auth.service';

@Component({
  selector: 'app-topbar',
  standalone: true,
  imports: [CommonModule, RouterModule],
  template: `
    <div class="layout-topbar">
      <div class="layout-topbar-start">
        <button #menubutton class="p-link layout-menu-button layout-topbar-button" (click)="onMenuToggle()">
          <i class="pi pi-bars"></i>
        </button>

        <a class="layout-topbar-logo ml-4" routerLink="/">
          <i class="pi pi-shield text-primary mr-2" style="font-size: 1.5rem"></i>
          <span class="font-bold text-900" style="font-size: 1.5rem">Zanshin</span>
        </a>
      </div>

      <div class="layout-topbar-end">
        <button #topbarmenubutton class="p-link layout-topbar-menu-button layout-topbar-button" (click)="onTopbarMenuToggle()">
          <i class="pi pi-ellipsis-v"></i>
        </button>

        <div #topbarmenu class="layout-topbar-menu" [ngClass]="{ 'layout-topbar-menu-mobile-active': layoutService.state().profileSidebarActive }">
          <button class="p-link layout-topbar-button" (click)="toggleDarkMode()">
            <i class="pi" [ngClass]="{'pi-moon': !layoutService.isDarkTheme(), 'pi-sun': layoutService.isDarkTheme()}"></i>
            <span>Theme</span>
          </button>
          
          <ng-container *ngIf="authService.user() as user">
            <div class="flex align-items-center gap-2 px-3 border-left-1 border-300">
                <img [src]="user.avatarUrl" *ngIf="user.avatarUrl" [alt]="user.username" class="border-circle" style="width: 32px; height: 32px;">
                <div class="flex flex-column">
                  <span class="font-medium hidden md:block line-height-1">{{ user.displayName || user.username }}</span>
                  <span class="text-xs font-bold px-2 py-0 border-round uppercase w-fit" 
                        [ngClass]="getRoleClass(user.role)">
                    {{ user.role }}
                  </span>
                </div>
            </div>
          </ng-container>

          <button class="p-link layout-topbar-button" (click)="logout()">
            <i class="pi pi-sign-out"></i>
            <span>Déconnexion</span>
          </button>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .border-left-1 { border-left: 1px solid var(--surface-border); }
  `]
})
export class AppTopbar {
  layoutService = inject(LayoutService);
  authService = inject(AuthService);

  @ViewChild('menubutton') menuButton!: ElementRef;
  @ViewChild('topbarmenubutton') topbarMenuButton!: ElementRef;
  @ViewChild('topbarmenu') menu!: ElementRef;

  onMenuToggle() {
    this.layoutService.onMenuToggle();
  }

  onTopbarMenuToggle() {
    this.layoutService.state.update((prev) => ({ ...prev, profileSidebarActive: !prev.profileSidebarActive }));
  }

  toggleDarkMode() {
    this.layoutService.toggleDarkMode();
  }

  logout() {
    this.authService.logout();
  }

  getRoleClass(role: string): string {
    switch (role) {
      case 'superuser': return 'bg-purple-100 text-purple-700';
      case 'admin': return 'bg-blue-100 text-blue-700';
      case 'user': return 'bg-gray-100 text-gray-700';
      default: return 'bg-gray-100 text-gray-700';
    }
  }
}
