import { Session } from './interfaces';

declare module 'express-serve-static-core' {
  interface Request {
    session?: Session | null;
  }
}