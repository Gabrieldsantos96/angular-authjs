// auth-router.ts
import express, { Request, Response, NextFunction } from 'express';
import * as jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import {
  AuthRouterConfig,
  ProviderConfig,
  Session,
  SignInCommand,
} from './interfaces';
import { ErrorResponse } from './interfaces';
import { InvalidArgumentException, NotFoundException } from './extensions';
import { sessionMiddleware } from './session-middleware';
import { writeResponseToNodeResponse } from '@angular/ssr/node';

function createJwt(session: Session, secret: string) {
  return jwt.sign(session, secret, { expiresIn: '3h' });
}

const OAUTH_ENDPOINTS: Record<
  string,
  { authorizeUrl: string; tokenUrl: string; userInfoUrl: string }
> = {
  github: {
    authorizeUrl: 'https://github.com/login/oauth/authorize',
    tokenUrl: 'https://github.com/login/oauth/access_token',
    userInfoUrl: 'https://api.github.com/user',
  },
  google: {
    authorizeUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    userInfoUrl: 'https://openidconnect.googleapis.com/v1/userinfo',
  },
};

async function handleOAuthCallback(
  provider: ProviderConfig,
  code: string
): Promise<Session | null> {
  try {
    const endpoints = OAUTH_ENDPOINTS[provider.type];

    const token = await fetch(endpoints.tokenUrl, {
      method: 'POST',
      body: JSON.stringify({
        code: '',
        client_id: provider.clientId,
        client_secret: provider.clientSecret,
        redirect_uri: provider.redirectUri,
        grant_type: 'authorization_code',
      }),
    }).then((s) => s.json());

    const accessToken = token?.data?.access_token || token?.data?.accessToken;

    if (!accessToken) return null;

    const user = await fetch(endpoints.userInfoUrl, {
      method: 'GET',
      headers: { Authorization: `Bearer ${accessToken}` },
    }).then((s) => s.json());

    const profile = user.data;

    return {
      user: {
        id: profile.id ?? profile.sub,
        email: profile.email,
        name: profile.name || profile.login,
      },
      expires: '',
    };
  } catch (err) {
    console.error('OAuth callback error:', err);
    return null;
  }
}

export function createAuthenticationRouter(config: AuthRouterConfig) {
  const router = express.Router();
  router.use(express.json());
  router.use(cookieParser());
  router.use(sessionMiddleware);

  router.post(
    '/api/auth/sign-in/:provider',
    async (
      req: Request<
        { provider: string },
        Session | ErrorResponse,
        SignInCommand & { code?: string }
      >,
      res: Response
    ) => {
      const provider = req.params.provider;
      const { username, password, callbackUrl = '/', code } = req.body;
      const providerConfig = config.providers.find((p) => p.id === provider);

      if (!providerConfig) throw new NotFoundException('PROVIDER CONFIG');

      if (providerConfig.type === 'credentials') {
        if (!username || !password) throw new InvalidArgumentException();

        try {
          const data = await providerConfig.authorize({ username, password });
          if (!data || !data.user) return res.status(401).end();

          const maxTime = config?.maxTime || 3 * 60 * 60 * 1000;

          const session: Session = {
            user: data.user,
            expires: new Date(Date.now() + maxTime).toISOString(),
          };

          const token = createJwt(session, config.secret);

          res.cookie('auth-csrtoken', token, {
            httpOnly: true,
            maxAge: config.maxTime,
            sameSite: 'strict',
            secure: process.env['NODE_ENV'] === 'production',
          });

          return res.json({ redirectTo: callbackUrl });
        } catch (err) {
          return res.status(500).json(err).end();
        }
      }

      if (
        providerConfig.type === 'github' ||
        providerConfig.type === 'google'
      ) {
        if (!code) {
          const endpoints = OAUTH_ENDPOINTS[providerConfig.type];
          const authUrl = `${endpoints.authorizeUrl}?client_id=${providerConfig.clientId}&redirect_uri=${providerConfig.redirectUri}&response_type=code&scope=openid%20email%20profile`;
          return res.json({ redirectTo: authUrl });
        }

        const session = await handleOAuthCallback(providerConfig, code);

        if (!session) return res.status(401).end();

        const maxTime = config?.maxTime || 3 * 60 * 60 * 1000;
        session.expires = new Date(Date.now() + maxTime).toISOString();

        const token = createJwt(session, config.secret);

        res.cookie('auth-csrtoken', token, {
          httpOnly: true,
          maxAge: config.maxTime,
          sameSite: 'strict',
          secure: process.env['NODE_ENV'] === 'production',
        });

        return res.json({ redirectTo: callbackUrl });
      }

      return null;
    }
  );

  router.get('/api/auth/callback/:provider', async (req: any, res) => {
    const provider = req.params.provider;
    const code = req.query.code as string;
    const providerConfig = config.providers.find((p) => p.id === provider);

    if (!providerConfig) throw new NotFoundException('PROVIDER CONFIG');
    if (!code) return res.status(400).json({ error: 'Missing code' });

    const session = await handleOAuthCallback(providerConfig, code);
    if (!session) return res.status(401).end();

    const maxTime = config?.maxTime || 3 * 60 * 60 * 1000;
    session.expires = new Date(Date.now() + maxTime).toISOString();

    const token = createJwt(session, config.secret);

    res.cookie('auth-csrtoken', token, {
      httpOnly: true,
      maxAge: config.maxTime,
      sameSite: 'strict',
      secure: process.env['NODE_ENV'] === 'production',
    });

    return res.redirect('/');
  });

  router.post('/api/auth/sign-out', (req, res) => {
    const { callbackUrl = '/' } = req.body;
    res.clearCookie('auth-csrtoken');
    return res.json(callbackUrl).end();
  });

  router.get('/api/auth/session', (request, res) => {
    const req = request as unknown as Request & { session: Session };
    try {
      if (!req.session) return res.status(401).end();

      const session = req.session as Session;
      const expiresAt = new Date(session.expires).getTime();

      const maxTime = config?.maxTime || 3 * 60 * 60 * 1000;

      if (Date.now() < expiresAt) {
        const newSession: Session = {
          ...session,
          expires: new Date(Date.now() + maxTime).toISOString(),
        };
        const token = createJwt(newSession, config.secret);

        res.cookie('auth-csrtoken', token, {
          httpOnly: true,
          maxAge: config.maxTime,
          sameSite: 'strict',
          secure: process.env['NODE_ENV'] === 'production',
        });

        return res.status(200).json(newSession);
      }

      res.clearCookie('auth-csrtoken');
      return res.status(401).end();
    } catch {
      res.clearCookie('auth-csrtoken');
      return res.status(401).end();
    }
  });

  router.use(async (request: Request, res: Response, next: NextFunction) => {
    const req = request as unknown as Request & { session: Session };
    try {
      if (!!config.angularApp && !!config.bootstrap) {
        const response = await config.angularApp.handle(req, {
          bootstrap: config.bootstrap,
          context: { session: req.session },
        });
        if (response) {
          return writeResponseToNodeResponse(response, res);
        }
      }

      const path = req.originalUrl.replace(/^\//, '');

      if (config.protectedRoutes?.includes(path)) {
        const callbackUrl = encodeURIComponent(req.originalUrl);
        return res.redirect(`/unauthorized?callbackUrl=${callbackUrl}`);
      }

      return res.redirect('/not-found');
    } catch (err) {
      next(err);
    }
  });

  return router;
}
