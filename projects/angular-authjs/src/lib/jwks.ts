import { pem2jwk } from 'pem-jwk';
import { PUBLIC_KEY } from './read-key-file';


export function getJwks() {
  const jwk = pem2jwk(PUBLIC_KEY);
  jwk['kid'] = 'authjs';
  jwk['alg'] = 'RS256';
  jwk['use'] = 'sig';

  return { keys: [jwk] };
}