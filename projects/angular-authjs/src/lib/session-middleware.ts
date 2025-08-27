// src/auth.middleware.ts
import { Request, Response, NextFunction } from 'express';
import * as jwt from 'jsonwebtoken';
import { Session } from './interfaces';
import { NotFoundException } from './extensions';

export function sessionMiddleware(
  request: Request,
  _: Response,
  next: NextFunction
) {
  let req = request as unknown as Request & { session: Session | null };

  try {
    req.session = null;
    const AUTH_COOKIE_NAME = process.env['AUTH_COOKIE_NAME'];

    if (!AUTH_COOKIE_NAME) {
      throw new NotFoundException('AUTH_COOKIE_NAME');
    }

    const AUTH_SECRET = process.env['AUTH_SECRET'];

    if (!AUTH_SECRET) {
      throw new NotFoundException('AUTH_COOKIE_NAME');
    }

    const token = req.cookies?.[AUTH_COOKIE_NAME];

    if (token) {
      const session = jwt.verify(token, AUTH_SECRET) as Session;
      req.session = session;
    }

    next();
  } catch (error) {
    req.session = null;
    next();
  }
}
