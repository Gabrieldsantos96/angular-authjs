# Angular Authjs

This project was generated using [Angular CLI](https://github.com/angular/angular-cli) version 20.2.0.

---

## Getting Started

### Creating an Angular Project with SSR

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

   ```ts
   //server.ts
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
           secret: crypto.randomUUID(),
           authorize: async (credentials) => {
             // external backend call or add prisma client with mongo
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
         // Example for future providers:
         // {
         // type: 'github',
         // clientId: 'YOUR_GITHUB_CLIENT_ID',
         // clientSecret: 'YOUR_GITHUB_CLIENT_SECRET',
         // },
         // {
         // type: 'google',
         // clientId: 'YOUR_GOOGLE_CLIENT_ID',
         // clientSecret: 'YOUR_GOOGLE_CLIENT_SECRET',
         // },
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
