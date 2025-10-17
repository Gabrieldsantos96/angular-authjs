import fs from 'fs';
import path from 'path';

export const PRIVATE_KEY = fs.readFileSync(path.resolve(process.cwd(), 'keys/private.key'), 'utf8');
export const PUBLIC_KEY = fs.readFileSync(path.resolve(process.cwd(), 'keys/public.key'), 'utf8');