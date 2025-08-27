import { AngularNodeAppEngine } from '@angular/ssr/node';

export type ProviderId = 'github' | 'credentials' | 'google';

export interface BaseProvider {
  id: ProviderId;
  clientId?: string;
  clientSecret?: string;
  authorizationUrl?: string;
  tokenUrl?: string;
  userInfoUrl?: string;
}

export interface OAuthProvider extends BaseProvider {
  type: 'github' | 'google';
}

export interface CredentialsProvider extends BaseProvider {
  type: 'credentials';
  secret: string;
  authorize: (credentials: {
    username: string;
    password: string;
  }) => Promise<Session>;
}

export type ProviderConfig = OAuthProvider | CredentialsProvider;

export interface AuthRouterConfig {
  providers: ProviderConfig[];
  secret: string;
  protectedRoutes?: string[];
  angularApp?: AngularNodeAppEngine;
  bootstrap?: unknown;
  maxTime?: number;
}

export interface SignInCommand {
  provider: ProviderId;
  username?: string;
  password?: string;
  callbackUrl?: string;
  code?: string;
}

export interface Session {
  user: {
    id?: string;
    name?: string;
    email?: string;
    image?: string;
  };
  expires: string;
  accessToken?: string;
}

export interface ErrorResponse {
  error: string;
}
