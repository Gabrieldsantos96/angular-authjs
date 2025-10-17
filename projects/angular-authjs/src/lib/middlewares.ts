import { Request, Response, NextFunction } from 'express';
import { Session } from './interfaces';
import { NotFoundException } from './extensions';
import { verifyJwt } from './jwt-helper';

export function session(secret: string) {
  return (request: Request, _: Response, next: NextFunction) => {
    let req = request as unknown as Request & { session: Session | null };
    req.session = null;

    if (!secret) {
      throw new NotFoundException('AUTH_SECRET');
    }
    
    const token = req.cookies?.['auth-csrtoken'];


    if (token) {
      try {
        const session = verifyJwt(token) as Session;
        req.session = session;
      } catch (err) {
        console.error(err);
        req.session = null;
      }
    }

    next();
  };
}

