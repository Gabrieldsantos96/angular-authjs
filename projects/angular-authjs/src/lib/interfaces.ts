import { Routes } from '@angular/router';
import { AngularNodeAppEngine } from '@angular/ssr/node';
import { OAuthProviderClass } from './providers/abstract-class';

export const enum ProviderId {
  credentials = "credentials",
  github = "github",
  google = "google",
  outlook = "outlook",
  supabase = "supabase"
}


export interface User {
  name: string;
  email: string | null;
  image?: string;
}

export interface Session {
  user: User;
  expires: string;
  access_token?: string;
  id_token?: string;
  refresh_token?: string;
  issuedAt?: string;
}

export interface ErrorResponse {
  error: string;
}

export interface ProviderBaseEnvironment {
  type: ProviderId;
  redirectUri: string;
  clientId: string;
  clientSecret: string;
}

export interface OAuthProviderConfig extends ProviderBaseEnvironment {
  type: ProviderId.github | ProviderId.google;
}

export interface SupabaseProviderConfig extends ProviderBaseEnvironment {
  type: ProviderId.supabase;
  supabaseUrl: string;
}

export interface OutlookProviderConfig extends ProviderBaseEnvironment {
  type: ProviderId.outlook;
  tenant: string;
}

export interface CredentialsProviderConfig extends ProviderBaseEnvironment {
  type: ProviderId.credentials;
  backendUrl: string;
  clientId: string;
  clientSecret: string;
}

export type ProviderConfig =
  | OAuthProviderConfig
  | SupabaseProviderConfig
  | OutlookProviderConfig
  | CredentialsProviderConfig;


export interface AuthRouterConfig {
  providers: OAuthProviderClass[];
  routes: Routes;
  secret: string;
  unauthorizeRoutePath?: string;
  angularApp: AngularNodeAppEngine;
}


export type SignInCommand = {
  username: string;
  password: string;
  callbackUrl?: string;
  provider: ProviderId.credentials
} | {
  code: string;
  provider: Exclude<ProviderId, ProviderId.credentials>;
  callbackUrl?: string;
}