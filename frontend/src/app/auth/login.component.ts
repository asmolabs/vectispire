import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule, ReactiveFormsModule, FormBuilder, Validators } from '@angular/forms';
import { Router, ActivatedRoute } from '@angular/router';
import { ButtonModule } from 'primeng/button';
import { CardModule } from 'primeng/card';
import { DividerModule } from 'primeng/divider';
import { InputTextModule } from 'primeng/inputtext';
import { PasswordModule } from 'primeng/password';
import { MessageModule } from 'primeng/message';
import { AuthService } from './auth.service';
import { SettingsService, AuthSettings } from '../settings/settings.service';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [
    CommonModule, 
    ButtonModule, 
    CardModule, 
    DividerModule, 
    FormsModule, 
    ReactiveFormsModule, 
    InputTextModule, 
    PasswordModule,
    MessageModule
  ],
  template: `
    <div class="login-container flex align-items-center justify-content-center min-vh-100 p-4">
      <p-card class="login-card w-full md:w-30rem">
        <div class="text-center mb-5">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="mb-3 text-primary">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
            </svg>
            <h1 class="text-3xl font-bold m-0 mb-2">Zanshin</h1>
            <p class="text-600 m-0">{{ isRegistering ? 'Créer un compte' : 'Veuillez vous connecter pour continuer' }}</p>
        </div>

        <div class="flex flex-column gap-3">
            <!-- Local Auth Form -->
            <form [formGroup]="authForm" (ngSubmit)="onSubmit()" class="flex flex-column gap-3">
                <div class="field flex flex-column gap-2">
                    <label for="username" class="font-bold">Nom d'utilisateur</label>
                    <input pInputText id="username" formControlName="username" placeholder="Entrez votre nom d'utilisateur" class="w-full" />
                </div>

                <div class="field flex flex-column gap-2" *ngIf="isRegistering">
                    <label for="email" class="font-bold">Email</label>
                    <input pInputText id="email" formControlName="email" type="email" placeholder="Entrez votre email" class="w-full" />
                </div>

                <div class="field flex flex-column gap-2" *ngIf="isRegistering">
                    <label for="displayName" class="font-bold">Nom d'affichage</label>
                    <input pInputText id="displayName" formControlName="displayName" placeholder="Entrez votre nom complet" class="w-full" />
                </div>

                <div class="field flex flex-column gap-2">
                    <label for="password" class="font-bold">Mot de passe</label>
                    <p-password 
                        id="password" 
                        formControlName="password" 
                        [toggleMask]="true" 
                        [feedback]="isRegistering"
                        placeholder="Entrez votre mot de passe"
                        styleClass="w-full"
                        inputStyleClass="w-full">
                    </p-password>
                </div>

                <p-button 
                    [label]="isRegistering ? 'S\\'enregistrer' : 'Se connecter'" 
                    type="submit"
                    styleClass="w-full p-button-primary mt-2" 
                    [loading]="loading"
                    [disabled]="authForm.invalid">
                </p-button>

                <div class="text-center" *ngIf="registrationAllowed || isRegistering">
                    <a href="javascript:void(0)" (click)="toggleMode()" class="text-primary font-medium">
                        {{ isRegistering ? 'Déjà un compte ? Se connecter' : 'Pas de compte ? S\\'enregistrer' }}
                    </a>
                </div>

            </form>



            <ng-container *ngIf="settings.githubEnabled || settings.keycloakEnabled">
                <p-divider align="center">
                    <span class="text-400 font-medium">OU</span>
                </p-divider>

                <div class="flex flex-column gap-3">
                    <p-button *ngIf="settings.githubEnabled"
                        label="Se connecter avec GitHub" 
                        icon="pi pi-github" 
                        styleClass="w-full p-button-secondary" 
                        (onClick)="loginWithGitHub()"
                        [disabled]="loading">
                    </p-button>
                    
                    <p-button *ngIf="settings.keycloakEnabled"
                        label="Se connecter avec Keycloak" 
                        icon="pi pi-lock" 
                        styleClass="w-full" 
                        (onClick)="loginWithKeycloak()"
                        [loading]="loading">
                    </p-button>
                </div>
            </ng-container>
            
            <div class="text-center mt-3" *ngIf="error">
                <p-message severity="error" [text]="error"></p-message>
            </div>
        </div>
      </p-card>
    </div>
  `,
  styles: [`
    .login-container {
      background: linear-gradient(135deg, var(--primary-color-50, #f8fafc) 0%, var(--primary-color-100, #f1f5f9) 100%);
      min-height: 100vh;
    }
    :host ::ng-deep .login-card .p-card-body {
      padding: 2.5rem;
      border-radius: 1rem;
      box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
    }
    .field label {
        margin-bottom: 0.5rem;
    }
  `]
})
export class LoginComponent implements OnInit {
  private authService = inject(AuthService);
  private settingsService = inject(SettingsService);
  private route = inject(ActivatedRoute);
  private router = inject(Router);
  private fb = inject(FormBuilder);

  loading = false;
  error = '';
  isRegistering = false;
  settings: AuthSettings = { githubEnabled: false, keycloakEnabled: false };

  registrationAllowed = true;
  authForm = this.fb.group({
    username: ['', [Validators.required, Validators.minLength(3)]],
    password: ['', [Validators.required, Validators.minLength(6)]],
    email: [''],
    displayName: ['']
  });

  ngOnInit() {
    this.settingsService.getAuthSettings().subscribe(settings => {
      this.settings = settings;
    });
    this.authService.getRegistrationStatus().subscribe(status => {
      this.registrationAllowed = status.allowed;
    });
    if (this.authService.isAuthenticated()) {
      this.router.navigate(['/']);
    }
    
    this.route.queryParams.subscribe(() => {
        if (this.authService.isAuthenticated()) {
            this.router.navigate(['/']);
        }
    });
  }

  toggleMode() {
    this.isRegistering = !this.isRegistering;
    this.error = '';


    
    if (this.isRegistering) {
        this.authForm.get('email')?.setValidators([Validators.required, Validators.email]);
        this.authForm.get('displayName')?.setValidators([Validators.required]);
    } else {
        this.authForm.get('email')?.clearValidators();
        this.authForm.get('displayName')?.clearValidators();
    }
    this.authForm.get('email')?.updateValueAndValidity();
    this.authForm.get('displayName')?.updateValueAndValidity();
  }

  onSubmit() {
    if (this.authForm.invalid) return;

    this.loading = true;
    this.error = '';

    const action = this.isRegistering 
        ? this.authService.registerLocal(this.authForm.value)
        : this.authService.loginLocal(this.authForm.value);

    action.subscribe({
        next: () => {
            if (this.isRegistering) {
                this.toggleMode();
                this.error = 'Compte créé avec succès. Veuillez vous connecter.';
            }
            this.loading = false;
        },
        error: (err: any) => {
            this.error = err.error?.message || 'Une erreur est survenue';
            this.loading = false;
        }
    });
  }

  loginWithGitHub() {
    this.authService.loginWithGitHub();
  }

  loginWithKeycloak() {
    this.authService.loginWithKeycloak();
  }
}
