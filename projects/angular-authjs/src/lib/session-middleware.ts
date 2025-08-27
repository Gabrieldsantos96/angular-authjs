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

    const AUTH_SECRET = process.env['AUTH_SECRET'];

    if (!AUTH_SECRET) {
      throw new NotFoundException('AUTH_SECRET');
    }

    const token = req.cookies?.['auth-csrtoken'];

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
