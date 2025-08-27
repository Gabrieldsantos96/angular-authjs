import {
  PLATFORM_ID,
  makeStateKey,
  TransferState,
  inject,
  REQUEST_CONTEXT,
} from '@angular/core';
import { CanActivateFn } from '@angular/router';
import { isPlatformServer } from '@angular/common';
import { Session } from './interfaces';

interface IRequestContext {
  context: {
    session: Session;
  };
}

const SESSION_KEY = makeStateKey<Session>('session');

export const RouteGuard: CanActivateFn = () => {
  const platformId = inject(PLATFORM_ID);
  const transferState = inject(TransferState);
  const ctx = inject(REQUEST_CONTEXT, {
    optional: true,
  }) as unknown as IRequestContext;

  if (isPlatformServer(platformId)) {
    const session = ctx?.context?.session as Session | null;
    if (!!session) {
      return true;
    }

    return false;
  } else {
    if (transferState.hasKey(SESSION_KEY)) {
      const session = transferState.get(SESSION_KEY, null);
      return !!session;
    }
    return false;
  }
};
