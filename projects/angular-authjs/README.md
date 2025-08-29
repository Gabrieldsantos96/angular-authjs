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

Integrate the angular-authjs library into your Angular application with SSR. Below is an example of how to set it up in your server.ts file, including the implementation of GitHub and Google OAuth providers:

```ts
//server.ts
// server.ts
import { createAuthenticationRouter, protectedRoutes } from "angular-authjs";
import { bootstrapApplication } from "@angular/platform-browser";
import { AppComponent, routes } from "./app/app.component";
import { environment } from "./environments/environment";
import { provideServerRendering } from "@angular/platform-server";
import * as crypto from "crypto";

const angularApp = bootstrapApplication(AppComponent, {
  providers: [provideServerRendering()],
});

app.use(
  createAuthenticationRouter({
    providers: [
      {
        type: "credentials",
        id: "credentials",
        secret: crypto.randomUUID(),
        authorize: async (credentials) => {
          // External backend call or add Prisma client with MongoDB
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
        redirectUri: "http://localhost:4200/api/auth/callback/github", // Adjust this URL
      } as ProviderConfig,
      {
        type: "google",
        id: "google",
        clientId: environment["GOOGLE_CLIENT_ID"]!,
        clientSecret: environment["GOOGLE_CLIENT_SECRET"]!,
        redirectUri: "http://localhost:4200/api/auth/callback/google", // Adjust this URL
      } as ProviderConfig,
    ],
    secret: environment["AUTH_SECRET"]!,
    protectedRoutes: protectedRoutes(routes),
    angularApp,
    bootstrap: angularApp,
  })
);
```

6. Defining Protected Routes

The protectedRoutes function checks which routes use guards.
Create the following components for redirection with callbackUrl:

UnauthorizedComponent → unauthorized route

NotFoundComponent → not-found route

```ts
const routes = [
  { path: "unauthorized", component: UnauthorizedComponent },
  { path: "not-found", component: NotFoundComponent },
  // Add your protected routes here with guards
];
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
