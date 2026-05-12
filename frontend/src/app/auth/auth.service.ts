import { Injectable, inject, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Router } from '@angular/router';
import { tap, catchError, of } from 'rxjs';

export interface User {
  id: number;
  githubId?: string;
  keycloakId?: string;
  username: string;
  email: string;
  avatarUrl?: string;
  displayName: string;
  role: 'superuser' | 'admin' | 'user';
}

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private http = inject(HttpClient);
  private router = inject(Router);
  private baseUrl = 'http://localhost:8080/api/auth';

  user = signal<User | null>(null);
  isAuthenticated = signal<boolean>(false);

  constructor() {
    this.getMe().subscribe();
  }

  getMe() {
    return this.http.get<User>(`${this.baseUrl}/me`).pipe(
      tap(user => {
        this.user.set(user);
        this.isAuthenticated.set(true);
      }),
      catchError(() => {
        this.user.set(null);
        this.isAuthenticated.set(false);
        return of(null);
      })
    );
  }

  loginWithGitHub() {
    window.location.href = `${this.baseUrl}/github`;
  }

  loginWithKeycloak() {
    window.location.href = `${this.baseUrl}/keycloak`;
  }

  loginLocal(credentials: any) {
    return this.http.post<any>(`${this.baseUrl}/login`, credentials).pipe(
      tap(response => {
        this.user.set(response.user);
        this.isAuthenticated.set(true);
        this.router.navigate(['/']);
      })
    );
  }

  registerLocal(userData: any) {
    return this.http.post(`${this.baseUrl}/register`, userData);
  }

  getRegistrationStatus() {
    return this.http.get<{ allowed: boolean }>(`${this.baseUrl}/registration-status`);
  }


  handleCallback() {
    return this.getMe().pipe(
      tap(() => {
        this.router.navigate(['/']);
      })
    );
  }

  logout() {
    this.http.get(`${this.baseUrl}/logout`).subscribe(() => {
      this.user.set(null);
      this.isAuthenticated.set(false);
      this.router.navigate(['/login']);
    });
  }

  getToken(): string | null {
    // Tokens are now stored in HttpOnly cookies and cannot be accessed from JS
    return null;
  }
}
