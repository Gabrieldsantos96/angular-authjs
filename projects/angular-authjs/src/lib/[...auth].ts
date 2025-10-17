import express, { Request, Response, NextFunction } from 'express';
import cookieParser from 'cookie-parser';
import { writeResponseToNodeResponse } from '@angular/ssr/node';
import { session } from './middlewares';
import { getProtectedRoutes } from './route-helpers';
import { AuthRouterConfig, ErrorResponse, ProviderId, Session, SignInCommand } from './interfaces';
import { createJwt } from './jwt-helper';
import { getJwks } from './jwks';



export function createAuthenticationRouter(config: AuthRouterConfig) {
  const router = express.Router();
  router.use(express.json());
  router.use(cookieParser());
  router.use(session(config.secret));

  router.post(
    '/api/auth/sign-in/:provider',
    async (
      req: Request<
        { provider: string },
        Session | ErrorResponse,
        SignInCommand
      >,
      res: Response
    ) => {
      const providerId = req.params.provider;
      const provider = config.providers.find((p) => p.config.type === providerId);

      if (!provider) {
        return res.status(404).json({ error: 'Provider not found.' });
      }

      const authUrl = provider.authorize(req.body.provider === ProviderId.credentials ? req.body : req.body.callbackUrl || '/');
      return res.json({ redirectUri: authUrl });
    }
  );

  router.get('/api/auth/callback/:provider', async (req: Request, res) => {
    const providerId = req.params['provider'];
    const code = req.query['code'] as string;
    const state = req.query['state'] as string;

    const provider = config.providers.find((p) => p.config.type === providerId);

    if (!provider) {
      return res.status(404).json({ error: 'Provider not found.' });
    }
    if (!code) {
      return res.status(400).json({ error: 'Missing Code' });
    }

    const result = await provider.callback<Session>(code);

    if (!result) {
      return res.status(401).json({ error: 'OAuth: Authentication failed' });
    }

    const session: Session = {
      user: {
        name: result.user.name,
        email: result.user.email,
        image: result.user.image,
      },
      access_token: result.access_token,
      id_token: result.id_token,
      expires: result.expires,
      issuedAt: new Date().toISOString(),
    };

    const token = createJwt(session);

    res.cookie('auth-csrtoken', token, {
      httpOnly: true,
      maxAge: Number(session.expires) * 1000,
      sameSite: 'strict',
      secure: process.env['NODE_ENV'] === 'production',
      path: '/',
    });

    let redirectUrl = '';
    if (state) {
      try {
        const decodedState = JSON.parse(Buffer.from(state, 'base64').toString());

        if (typeof decodedState !== 'object' || !decodedState) {
          console.error('Invalid decodedState: not an object');
          return res.redirect(`http://localhost:4200?error=${encodeURIComponent('Invalid state')}`);
        }
        redirectUrl = `http://localhost:4200?redirectTo=${encodeURIComponent(decodedState.callbackUrl)}`;
      } catch (err) {
        console.error('Failed to decode state:', err);
        return res.redirect(`http://localhost:4200?error=${encodeURIComponent('Failed to decode state')}`);
      }
    }

    return res.redirect(redirectUrl);
  });

  router.post('/api/auth/sign-out', (req, res) => {
    const { callbackUrl = '/' } = req.body;
    res.clearCookie('auth-csrtoken');
    return res.json({ redirectTo: callbackUrl });
  });

  router.get('/api/auth/session', (request, res) => {
    const req = request as unknown as Request & { session: Session };
    try {
      if (!req.session) {
        res.clearCookie('auth-csrtoken');
        return res.status(401).json({ error: 'OAuth: No active session.' });
      }

      const session = req.session as Session;
      return res.status(200).json(session);
    } catch (error) {
      console.error('Session validation error:', error);
      res.clearCookie('auth-csrtoken');
      return res.status(401).json({ error: 'OAuth: Invalid Session.' });
    }
  });

 router.get('/api/auth/.well-known/jwks.json', async (_, res) => {
  try {
    const jwks = getJwks();
    res.json(jwks);
  } catch (err) {
    console.error('Error exporting JWKS:', err);
    res.status(500).json({ error: 'Failed to export JWKS' });
  }
});

  // router.use('/web-api/*', createProxyMiddleware({
  //   target: process.env.EXTERNAL_BACKEND_URL,
  //   changeOrigin: true,
  //   pathRewrite: { '^/external-api': '' },
  //   on: {
  //     proxyReq: (proxyReq, req: Request & { session?: Session }, res, options) => {
  //       if (!!req.cookies?.['e-auth-csrtoken']) {
  //         proxyReq.setHeader('Authorization', req.cookies?.['e-auth-csrtoken']);
  //       }
  //     },
  //     error: (err, req, res: Response) => {
  //       res.status(500).json({ error: 'Proxy error' });
  //     },
  //   },
  // }));


  router.use((req: Request, res: Response, next: NextFunction) => {
    const request = req;

    if (/^\/api(\/)?$/.test(request.originalUrl)) {
      return next();
    }

    const path = request.originalUrl.replace(/^\//, '');
    const protectedRoutes = getProtectedRoutes(config.routes);
    const isProtected = protectedRoutes.some((s) => s === path);

    if (isProtected && !request.session) {
      const path = config?.unauthorizeRoutePath || 'unauthorized';
      const callbackUrl = encodeURIComponent(request.originalUrl);
      return res.redirect(`/${path}?callbackUrl=${callbackUrl}`);
    }

    return config.angularApp
      .handle(request, {
        bootstrap: config.angularApp,
        context: { session: request.session },
      })
      .then((response) =>
        response ? writeResponseToNodeResponse(response, res) : next()
      )
      .catch(next);
  });

  return router;
}