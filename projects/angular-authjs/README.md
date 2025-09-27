OBS: UNDER DEVELOPMENT AND TESTS

# Angular Authjs

This project was generated using [Angular CLI](https://github.com/angular/angular-cli) version 20.2.0.

## Getting Started

### Creating an Angular Project with SSR

**angular-authjs** Uses a JWT (JSON Web Token) strategy stored in cookies for enhanced security.

To use the **angular-authjs** library, start by creating a new Angular project with **Server-Side Rendering (SSR)** support:

1. Install the Angular CLI globally (if not already installed):

   ```bash
   npm install -g @angular/cli
   ```

2. Create a new Angular project with SSR enabled:

   ```ts
   ng new my-auth-app --ssr
   ```

3. Navigate to the project directory:
   ```ts
   cd my-auth-app
   ```
4. Install package:
   ```ts
   npm install angular-authjs
   ```
5. How to use

Integrate the angular-authjs library into your Angular application with SSR. Below is an example of how to set it up in your server.ts file, including the implementation of GitHub and Google OAuth providers, this is how your server ts should be looked, delete the default writeResponseToNodeResponse function from your server.ts, as createAuthenticationRouter will handle the response for you. 

```ts
//server.ts
// server.ts
import {
  AngularNodeAppEngine,
  createNodeRequestHandler,
  isMainModule,
} from '@angular/ssr/node';
import { createAuthenticationRouter, getProtectedRoutes, getPublicRoutes, ProviderConfig, Session } from "angular-authjs";
import express from 'express';
import { join } from 'node:path';
import { routes } from './app/app.routes';
import { environment } from './environments/environment';

const browserDistFolder = join(import.meta.dirname, '../browser');

const app = express();
const angularApp = new AngularNodeAppEngine();

app.use(
  express.static(browserDistFolder, {
    maxAge: '1y',
    index: false,
    redirect: false,
  }),
);

app.use(
  createAuthenticationRouter({
    providers: [
      {
        type: "credentials",
        id: "credentials",
        secret: crypto.randomUUID(),
        authorize: async (credentials) => {
          return new Promise<Session>((resolve) => {
            setTimeout(() => {
              resolve({
                user: {
                  id: crypto.randomUUID(),
                  email: credentials.username,
                  name: "Gabriel",
                },
                expires: "",
              });
            }, 250);
          });
        },
      } as ProviderConfig,
      {
        type: "github",
        id: "github",
        clientId: environment["GITHUB_CLIENT_ID"]!,
        clientSecret: environment["GITHUB_CLIENT_SECRET"]!,
        redirectUri: "http://localhost:4200/api/auth/callback/github",
      } as ProviderConfig,
      {
        type: "google",
        id: "google",
        clientId: environment["GOOGLE_CLIENT_ID"]!,
        clientSecret: environment["GOOGLE_CLIENT_SECRET"]!,
        redirectUri: "http://localhost:4200/api/auth/callback/google",
      } as ProviderConfig,
    ],
    secret: environment["AUTH_SECRET"]!,
    protectedRoutes: getProtectedRoutes(routes),
    publicRoutes: getPublicRoutes(routes),
    angularApp,
    bootstrap: angularApp,
  })
);

if (isMainModule(import.meta.url)) {
  const port = process.env['PORT'] || 4000;
  app.listen(port, (error) => {
    if (error) {
      throw error;
    }

    console.log(`Node Express server listening on http://localhost:${port}`);
  });
}
export const reqHandler = createNodeRequestHandler(app);

```

6. Defining Protected Routes

The getProtectedRoutes function checks which routes use guards.
Create the following components for redirection with callbackUrl:

UnauthorizedComponent → unauthorized route

NotFoundComponent → not-found route

```ts

import { Routes } from '@angular/router';
import { RouteGuard } from 'angular-authjs';
import { UnauthorizedComponent } from './components/unauthorized.component';
import { NotFoundComponent } from './components/not-found.component';
import { DashboardComponent } from './components/dashboard.component';

import { LoginComponent } from './components/login.component';

export const routes: Routes = [
    { path: 'unauthorized', component: UnauthorizedComponent },
    { path: 'dashboard', component: DashboardComponent, canActivate: [RouteGuard] },
    { path: 'login', component: LoginComponent },
    { path: '**', component: NotFoundComponent },
];

```

Login Example

```ts

import { Component, OnInit, inject } from '@angular/core';
import { FormBuilder, FormGroup, Validators, ReactiveFormsModule } from '@angular/forms';
import { SessionProvider } from 'angular-authjs';
import { Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { signal } from '@angular/core';
import { filter } from 'rxjs';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule],
  template: `
    <h2>Login</h2>
    <form [formGroup]="loginForm" (ngSubmit)="onSubmit()">
      <label for="username">Usuário</label>
      <input id="username" formControlName="username" required />
      <div *ngIf="loginForm.get('username')?.invalid && loginForm.get('username')?.touched" style="color:red">Usuário é obrigatório</div>
      <label for="password">Senha</label>
      <input id="password" type="password" formControlName="password" required />
      <div *ngIf="loginForm.get('password')?.invalid && loginForm.get('password')?.touched" style="color:red">Senha é obrigatória</div>
      <button type="submit" [disabled]="loginForm.invalid">Entrar</button>
    </form>
    <button (click)="signInWithProvider('github')">Entrar com GitHub</button>
    <button (click)="signInWithProvider('google')">Entrar com Google</button>
    <div *ngIf="error()" style="color:red">{{ error() }}</div>
  `,
})
export class LoginComponent implements OnInit {
  loginForm: FormGroup;
  error = signal('');

  private sessionProvider = inject(SessionProvider);
  private router = inject(Router);
  private fb = inject(FormBuilder);

  constructor() {
    this.loginForm = this.fb.group({
      username: ['', Validators.required],
      password: ['', Validators.required],
    });
  }

  ngOnInit(): void {
    this.sessionProvider.isAuthenticated$
      .pipe(filter(isAuth => isAuth))
      .subscribe(() => {
        this.router.navigateByUrl('/dashboard');
      });
  }

  onSubmit() {
    if (this.loginForm.invalid) return;
    const { username, password } = this.loginForm.value;
    this.sessionProvider.signIn('credentials', {
      username,
      password,
      callbackUrl: '/dashboard',
    }).subscribe({
      next: (res) => {
        this.router.navigateByUrl(res.redirectTo);
      },
      error: () => {
        this.error.set('Usuário ou senha inválidos');
      }
    });
  }

  signInWithProvider(provider: 'github' | 'google') {
    this.sessionProvider.signIn(provider, {
      callbackUrl: '/dashboard',
    }).subscribe({
      next: (res) => {
        window.location.href = res.redirectTo;
      },
      error: () => {
        this.error.set(`Erro ao autenticar com ${provider}`);
      }
    });
  }
}

```

7. Using the SessionProvider Service

The **SessionProvider** service provides methods to manage authentication sessions, including sign-in with GitHub and Google. Below is the service implementation and how to use it:

```ts
// app.component.ts
import { Component, OnInit } from "@angular/core";
import { SessionProvider } from "./session-provider.service";
import { Router } from "@angular/router";

@Component({
  selector: "app-root",
  template: `
    <div *ngIf="isAuthenticated; else login">
      <p>Welcome, {{ session()?.user.name }}!</p>
      <button (click)="signOut()">Sign Out</button>
    </div>
    <ng-template #login>
      <button (click)="signInWithGitHub()">Sign In with GitHub</button>
      <button (click)="signInWithGoogle()">Sign In with Google</button>
    </ng-template>
  `,
})
export class AppComponent implements OnInit {
  session = this.sessionProvider.session.asObservable();
  isAuthenticated = false;

  constructor(private sessionProvider: SessionProvider, private router: Router) {}

  ngOnInit() {
    this.sessionProvider.getSession().subscribe({
      next: (session) => this.sessionProvider.session.set(session),
      error: () => this.sessionProvider.session.set(null),
    });
    this.isAuthenticated = this.sessionProvider.isAuthenticated();
  }

  signInWithGitHub() {
    this.sessionProvider.signIn("github", { callbackUrl: "/dashboard" }).subscribe({
      next: (response) => {
        window.location.href = response.redirectTo; // Redirect to GitHub auth URL
      },
      error: (error) => console.error("GitHub sign-in failed", error),
    });
  }

  signInWithGoogle() {
    this.sessionProvider.signIn("google", { callbackUrl: "/dashboard" }).subscribe({
      next: (response) => {
        window.location.href = response.redirectTo; // Redirect to Google auth URL
      },
      error: (error) => console.error("Google sign-in failed", error),
    });
  }

  signOut() {
    this.sessionProvider.signOut("/").subscribe({
      next: () => {
        this.sessionProvider.session.set(null);
        this.router.navigate(["/"]);
      },
      error: (error) => console.error("Sign-out failed", error),
    });
  }
}
```
