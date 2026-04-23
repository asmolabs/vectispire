import { inject } from '@angular/core';
import { Router, CanActivateFn } from '@angular/router';
import { AuthService } from './auth.service';

export const adminGuard: CanActivateFn = () => {
  const authService = inject(AuthService);
  const router = inject(Router);
  const user = authService.user();

  if (authService.isAuthenticated() && user && (user.role === 'admin' || user.role === 'superuser')) {
    return true;
  }

  // Redirect to home if not authorized
  router.navigate(['/']);
  return false;
};
