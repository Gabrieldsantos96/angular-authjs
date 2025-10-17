import { Routes } from '@angular/router';

export function getRoutePaths(routes: Routes): string[] {
  return routes
    .map((route) => route.path)
    .filter((path): path is string => !!path);
}

export function getProtectedRoutes(routes: Routes): string[] {
  return routes
    .filter(
      (route) =>
        Array.isArray(route.canActivate) && route.canActivate.length > 0 && !!route.canActivate.find(s => s === 'RouteGuard')
    )
    .map((route) => route.path!)
    .filter((path): path is string => !!path);
}

export function getPublicRoutes(routes: Routes): string[] {
  return routes
    .filter(
      (route) =>
        !route.canActivate
    )
    .map((route) => route.path!)
    .filter((path): path is string => !!path);
}

