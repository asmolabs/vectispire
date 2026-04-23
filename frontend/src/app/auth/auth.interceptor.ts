import { HttpInterceptorFn, HttpHandlerFn, HttpRequest } from '@angular/common/http';
import { inject } from '@angular/core';

export const authInterceptor: HttpInterceptorFn = (req: HttpRequest<unknown>, next: HttpHandlerFn) => {
  const cloned = req.clone({
    withCredentials: true
  });
  return next(cloned);
};
