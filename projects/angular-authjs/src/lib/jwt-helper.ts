import jwt from 'jsonwebtoken';
import { Session } from './interfaces';
import { PRIVATE_KEY, PUBLIC_KEY } from './read-key-file';

export function createJwt(session: Session) {
  return jwt.sign(session, PRIVATE_KEY, {
    algorithm: 'RS256',
    expiresIn: Number(session.expires),
  });
}

export function verifyJwt(token: string): string | jwt.JwtPayload {
  return jwt.verify(token, PUBLIC_KEY, {
    algorithms: ['RS256'],
  });
}
